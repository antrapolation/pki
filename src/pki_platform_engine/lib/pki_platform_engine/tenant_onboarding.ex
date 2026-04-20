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

  alias PkiPlatformEngine.{PlatformRepo, Provisioner, Tenant, TenantLifecycle}

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
    with {:ok, info} <- TenantLifecycle.create_tenant(%{id: tenant.id, slug: tenant.slug}),
         :ok <- TenantLifecycle.boot_tenant_apps(info.node, info.port) do
      {:ok, info}
    end
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
end
