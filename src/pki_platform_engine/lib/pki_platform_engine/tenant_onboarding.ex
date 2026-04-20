defmodule PkiPlatformEngine.TenantOnboarding do
  @moduledoc """
  Per-tenant BEAM onboarding pipeline.

  The provisioning chain wired by `PkiPlatformPortalWeb.TenantNewLive`:

    1. `register_tenant/3` — writes a `Tenant` row in the platform DB
       (status `"provisioning"`). This is the durable record; the
       actual tenant BEAM hasn't started yet.
    2. `spawn_beam/1` — asks `TenantLifecycle` to spawn a per-tenant
       BEAM via `:peer`, allocate a port, and boot the tenant app
       stack (`pki_tenant_web` + its deps) over RPC. Returns the
       child node + the port it's listening on.
    3. `bootstrap_first_admin/2` — RPCs into the tenant BEAM to
       create the first `ca_admin` user through
       `PkiTenant.PortalUserAdmin.create_user/1`. Returns the
       generated plaintext password for one-time display.
    4. `activate_tenant/1` — flips the platform Tenant row to
       `"active"`.

  CA/RA instances themselves are not created up-front anymore — the
  first `ca_admin` creates them explicitly via `/ca-instances` in the
  tenant portal, per the per-tenant-BEAM design.
  """

  alias PkiPlatformEngine.{
    EmailTemplates,
    Mailer,
    PlatformRepo,
    Provisioner,
    SofthsmTokenManager,
    Tenant,
    TenantLifecycle
  }

  require Logger

  @doc """
  Step 1 — write a Tenant row (platform DB).

  Arguments
    * `name`  — display name ("Acme Corp")
    * `slug`  — short URL-safe id ("acme")
    * `email` — admin contact email
  """
  @spec register_tenant(String.t(), String.t(), String.t()) ::
          {:ok, Tenant.t()} | {:error, term()}
  def register_tenant(name, slug, email) do
    Provisioner.register_tenant(name, slug, email: email)
  end

  @doc "Step 2 — spawn the per-tenant BEAM and boot its app stack."
  @spec spawn_beam(Tenant.t()) :: {:ok, map()} | {:error, term()}
  def spawn_beam(%Tenant{} = tenant) do
    # SoftHSM2 token init runs BEFORE peer spawn so we can pass
    # SOFTHSM2_CONF into the peer's process env at boot time — the
    # tenant's PKCS#11 calls then land in its dedicated slot instead
    # of the system default config. Best-effort: `:skipped` (no
    # softhsm2-util) or `{:error, _}` drops through to a non-isolated
    # peer instead of failing the wizard.
    softhsm_outcome = provision_softhsm_token(tenant)
    softhsm_conf = softhsm_conf_path_from(softhsm_outcome)

    create_attrs = %{id: tenant.id, slug: tenant.slug, softhsm_conf: softhsm_conf}

    with {:ok, info} <- TenantLifecycle.create_tenant(create_attrs),
         :ok <- TenantLifecycle.boot_tenant_apps(info.node, info.port) do
      {:ok, Map.put(info, :softhsm, softhsm_outcome)}
    end
  end

  defp softhsm_conf_path_from({:ok, %{conf_path: conf_path}}), do: conf_path
  defp softhsm_conf_path_from(_), do: nil

  @doc """
  Allocate a dedicated SoftHSM2 token for a tenant and record the
  coordinates in `tenants.metadata["softhsm"]`.

  Called from `spawn_beam/1` but also exposed for manual retries
  (e.g. if softhsm2-util was installed after the tenant was spawned).
  """
  @spec provision_softhsm_token(Tenant.t()) ::
          {:ok, map()} | {:ok, :skipped} | {:error, term()}
  def provision_softhsm_token(%Tenant{} = tenant) do
    case SofthsmTokenManager.init_tenant_token(tenant.slug) do
      {:ok, :skipped} = skip ->
        skip

      {:ok, info} ->
        persist_softhsm_metadata(tenant, info)
        {:ok, info}

      {:error, reason} = err ->
        Logger.warning(
          "[onboarding] softhsm token init failed for #{tenant.slug}: #{inspect(reason)}"
        )

        err
    end
  end

  defp persist_softhsm_metadata(%Tenant{} = tenant, info) do
    # PINs live on disk in the token dir (`.pins`, mode 0600) for
    # this first increment — do NOT copy them into metadata where
    # they'd land in Postgres in plaintext. Only coordinates go in
    # the DB.
    softhsm_meta = %{
      "conf_path" => info.conf_path,
      "tenant_dir" => info.tenant_dir,
      "slot_id" => info.slot_id,
      "label" => info.label,
      "library_path" => info.library_path,
      "provisioned_at" => DateTime.utc_now() |> DateTime.to_iso8601()
    }

    new_meta = Map.put(tenant.metadata || %{}, "softhsm", softhsm_meta)

    tenant
    |> Tenant.changeset(%{metadata: new_meta})
    |> PlatformRepo.update()
  rescue
    e ->
      Logger.warning(
        "[onboarding] failed to persist softhsm metadata for #{tenant.slug}: #{Exception.message(e)}"
      )

      :ok
  end

  @doc """
  Step 3 — create the first ca_admin on the tenant BEAM. Returns the
  generated password for one-shot display.
  """
  @spec bootstrap_first_admin(Tenant.t(), node()) ::
          {:ok, map(), String.t()} | {:error, term()}
  def bootstrap_first_admin(%Tenant{} = tenant, node) do
    attrs = %{
      username: "#{tenant.slug}-admin",
      display_name: "#{tenant.name} Admin",
      email: tenant.email,
      role: "ca_admin"
    }

    TenantLifecycle.create_initial_admin(node, attrs)
  end

  @doc "Step 4 — flip the Tenant row to status `active`."
  @spec activate_tenant(String.t()) :: {:ok, Tenant.t()} | {:error, term()}
  def activate_tenant(tenant_id) do
    case PlatformRepo.get(Tenant, tenant_id) do
      nil -> {:error, :not_found}
      tenant -> tenant |> Tenant.status_changeset(%{status: "active"}) |> PlatformRepo.update()
    end
  end

  @doc """
  Mark a tenant as `"failed"` with the failure reason recorded in
  `metadata.failure`. Called by the wizard whenever spawn / bootstrap /
  activate errors out so the row doesn't sit in `"provisioning"`
  forever.
  """
  @spec mark_failed(String.t(), term()) :: {:ok, Tenant.t()} | {:error, term()}
  def mark_failed(tenant_id, reason) do
    case PlatformRepo.get(Tenant, tenant_id) do
      nil -> {:error, :not_found}
      tenant -> tenant |> Tenant.failed_changeset(reason) |> PlatformRepo.update()
    end
  end

  @doc """
  Resume a stalled tenant by re-running spawn → admin → active.

  Idempotent: stops any running peer for this tenant first, releases
  its port, and starts fresh. Only runs for rows in `"provisioning"`
  or `"failed"` — already-active or suspended tenants return an
  error so we don't accidentally double-spawn.

  Returns `{:ok, %{tenant: tenant, beam: info, admin: %{username, password}}}`
  on success so the UI can display the new ca_admin password.
  """
  @spec resume_provisioning(String.t()) ::
          {:ok, map()} | {:error, term()}
  def resume_provisioning(tenant_id) do
    with {:ok, tenant} <- load_resumable(tenant_id),
         :ok <- reset_tenant_state(tenant),
         {:ok, info} <- spawn_beam(tenant),
         {:ok, user, plaintext} <- bootstrap_first_admin(tenant, info.node),
         {:ok, activated} <- activate_tenant(tenant_id) do
      portal_url = "http://#{tenant_portal_host()}:#{info.port}/"
      email_outcome = send_admin_invitation(activated, user.username, plaintext, portal_url: portal_url)

      {:ok,
       %{
         tenant: activated,
         beam: info,
         admin: %{username: user.username, password: plaintext},
         email: email_outcome
       }}
    else
      {:error, reason} ->
        _ = mark_failed(tenant_id, reason)
        {:error, reason}
    end
  end

  defp tenant_portal_host do
    System.get_env("TENANT_PORTAL_HOST", "localhost")
  end

  @doc """
  Best-effort invitation email after the first ca_admin is bootstrapped.

  Uses the shared `EmailTemplates.user_invitation/5` template (same
  one used for later portal user invites) so the email looks
  identical across the platform. The wizard also flashes the
  plaintext password to the admin for air-gapped deployments — this
  email is purely a convenience for the tenant contact.

  Returns `{:ok, :sent}` / `{:ok, :skipped}` / `{:error, reason}` so
  callers can audit the outcome, but must never block on mailer
  failure.
  """
  @spec send_admin_invitation(Tenant.t(), String.t(), String.t(), keyword()) ::
          {:ok, :sent | :skipped} | {:error, term()}
  def send_admin_invitation(%Tenant{} = tenant, username, password, opts \\ []) do
    portal_url = Keyword.get(opts, :portal_url, "")
    role_label = Keyword.get(opts, :role_label, "CA Admin")
    subject = "Your PKI platform admin credentials – #{tenant.name}"

    html =
      EmailTemplates.user_invitation(
        tenant.name,
        role_label,
        portal_url,
        username,
        password
      )

    case Mailer.send_email(tenant.email, subject, html) do
      {:ok, :sent} = ok ->
        Logger.info("[onboarding] ca_admin invitation emailed to #{tenant.email} for #{tenant.slug}")
        ok

      {:ok, :skipped} = skip ->
        Logger.info("[onboarding] RESEND_API_KEY not set; ca_admin invitation not emailed for #{tenant.slug}")
        skip

      {:error, reason} = err ->
        Logger.warning("[onboarding] ca_admin invitation email failed for #{tenant.slug}: #{inspect(reason)}")
        err
    end
  rescue
    e ->
      Logger.warning("[onboarding] ca_admin invitation email raised for #{tenant.slug}: #{Exception.message(e)}")
      {:error, :mailer_raised}
  end

  defp load_resumable(tenant_id) do
    case PlatformRepo.get(Tenant, tenant_id) do
      nil ->
        {:error, :not_found}

      %Tenant{status: s} = tenant when s in ["provisioning", "failed", "initialized"] ->
        {:ok, tenant}

      %Tenant{status: s} ->
        {:error, {:not_resumable, s}}
    end
  end

  # Stop any peer + release the port before re-spawning. Each step is
  # best-effort — a tenant that was never fully spawned may not have a
  # peer at all, and TenantLifecycle.stop_tenant returns :not_found in
  # that case which we ignore.
  defp reset_tenant_state(%Tenant{id: tenant_id}) do
    _ = TenantLifecycle.stop_tenant(tenant_id)
    _ = PkiPlatformEngine.PortAllocator.release(tenant_id)
    :ok
  end
end
