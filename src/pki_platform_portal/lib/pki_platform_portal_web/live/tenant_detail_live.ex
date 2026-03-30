defmodule PkiPlatformPortalWeb.TenantDetailLive do
  use PkiPlatformPortalWeb, :live_view

  alias PkiPlatformEngine.{Mailer, EmailTemplates}

  require Logger

  @impl true
  def mount(%{"id" => id}, _session, socket) do
    case PkiPlatformEngine.Provisioner.get_tenant(id) do
      nil ->
        {:ok,
         socket
         |> put_flash(:error, "Tenant not found.")
         |> push_navigate(to: "/tenants")}

      tenant ->
        if connected?(socket), do: send(self(), :load_metrics)
        ca_host = System.get_env("CA_PORTAL_HOST", "ca.straptrust.com")
        ra_host = System.get_env("RA_PORTAL_HOST", "ra.straptrust.com")

        {:ok,
         assign(socket,
           page_title: "Tenant Detail",
           tenant: tenant,
           metrics: %{db_size: 0, ca_users: 0, ra_users: 0, certificates_issued: 0, active_certificates: 0, pending_csrs: 0, ca_instances: 0, ra_instances: 0},
           ca_setup_url: "https://#{ca_host}/setup?tenant=#{tenant.slug}",
           ra_setup_url: "https://#{ra_host}/setup?tenant=#{tenant.slug}"
         )}
    end
  end

  @impl true
  def handle_event("suspend", _params, socket) do
    case PkiPlatformEngine.Provisioner.suspend_tenant(socket.assigns.tenant.id) do
      {:ok, updated_tenant} ->
        {:noreply,
         socket
         |> assign(tenant: updated_tenant)
         |> put_flash(:info, "Tenant \"#{updated_tenant.name}\" suspended.")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to suspend tenant: #{inspect(reason)}")}
    end
  end

  def handle_event("activate", _params, socket) do
    case PkiPlatformEngine.Provisioner.activate_tenant(socket.assigns.tenant.id) do
      {:ok, updated_tenant} ->
        {:noreply,
         socket
         |> assign(tenant: updated_tenant)
         |> put_flash(:info, "Tenant \"#{updated_tenant.name}\" activated.")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to activate tenant: #{inspect(reason)}")}
    end
  end

  def handle_event("delete", _params, socket) do
    case PkiPlatformEngine.Provisioner.delete_tenant(socket.assigns.tenant.id) do
      {:ok, _tenant} ->
        {:noreply,
         socket
         |> put_flash(:info, "Tenant deleted successfully.")
         |> push_navigate(to: "/tenants")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to delete tenant: #{inspect(reason)}")}
    end
  end

  def handle_event("resend_credentials", _params, socket) do
    tenant = socket.assigns.tenant
    send(self(), {:credential_action, :resend})
    {:noreply, put_flash(socket, :info, "Resending credentials to #{tenant.email}...")}
  end

  def handle_event("reset_ca_admin", _params, socket) do
    send(self(), {:credential_action, :reset_ca})
    {:noreply, put_flash(socket, :info, "Resetting CA Admin...")}
  end

  def handle_event("reset_ra_admin", _params, socket) do
    send(self(), {:credential_action, :reset_ra})
    {:noreply, put_flash(socket, :info, "Resetting RA Admin...")}
  end

  @impl true
  def handle_info({:credential_action, action}, socket) do
    tenant = socket.assigns.tenant
    secret = System.get_env("INTERNAL_API_SECRET", "")
    expires_at = DateTime.utc_now() |> DateTime.add(24, :hour) |> DateTime.truncate(:second)
    ca_host = System.get_env("CA_PORTAL_HOST", "ca.straptrust.com")
    ra_host = System.get_env("RA_PORTAL_HOST", "ra.straptrust.com")

    ca_username = "#{tenant.slug}-ca-admin"
    ra_username = "#{tenant.slug}-ra-admin"
    ca_password = :crypto.strong_rand_bytes(12) |> Base.url_encode64()
    ra_password = :crypto.strong_rand_bytes(12) |> Base.url_encode64()

    errors =
      case action do
        :resend ->
          # Just regenerate passwords and resend email — delete old users, create new ones
          delete_and_recreate_admin(:ca, ca_username, ca_password, tenant, secret, expires_at) ++
            delete_and_recreate_admin(:ra, ra_username, ra_password, tenant, secret, expires_at)

        :reset_ca ->
          delete_and_recreate_admin(:ca, ca_username, ca_password, tenant, secret, expires_at)

        :reset_ra ->
          delete_and_recreate_admin(:ra, ra_username, ra_password, tenant, secret, expires_at)
      end

    # Send credential email
    if errors == [] do
      {send_ca_u, send_ca_p, send_ra_u, send_ra_p} =
        case action do
          :resend -> {ca_username, ca_password, ra_username, ra_password}
          :reset_ca -> {ca_username, ca_password, ra_username, "(unchanged)"}
          :reset_ra -> {ca_username, "(unchanged)", ra_username, ra_password}
        end

      html = EmailTemplates.admin_credentials(
        tenant.name, send_ca_u, send_ca_p, send_ra_u, send_ra_p,
        "https://#{ca_host}", "https://#{ra_host}"
      )

      case Mailer.send_email(tenant.email, "Updated credentials for #{tenant.name}", html) do
        {:ok, _} -> :ok
        {:error, reason} -> Logger.error("Failed to send credential email: #{inspect(reason)}")
      end
    end

    # Reload metrics
    send(self(), :load_metrics)

    socket =
      if errors == [] do
        put_flash(socket, :info, "Credentials reset and emailed to #{tenant.email}")
      else
        put_flash(socket, :error, Enum.join(errors, "; "))
      end

    {:noreply, socket}
  end

  def handle_info(:load_metrics, socket) do
    metrics =
      try do
        PkiPlatformEngine.TenantMetrics.get_metrics(socket.assigns.tenant)
      catch
        _, _ -> %{db_size: 0, ca_users: 0, ra_users: 0, certificates_issued: 0, active_certificates: 0, pending_csrs: 0, ca_instances: 0, ra_instances: 0}
      end

    {:noreply, assign(socket, metrics: metrics)}
  end

  defp delete_and_recreate_admin(:ca, username, password, tenant, secret, expires_at) do
    # Delete existing CA admin
    case Req.get("http://127.0.0.1:4001/api/v1/users",
           headers: [{"x-internal-secret", secret}],
           params: [role: "ca_admin"],
           retry: false
         ) do
      {:ok, %{status: 200, body: users}} when is_list(users) ->
        for user <- users, user["username"] == username do
          Req.delete("http://127.0.0.1:4001/api/v1/users/#{user["id"]}",
            headers: [{"x-internal-secret", secret}], retry: false)
        end
      _ -> :ok
    end

    # Create new CA admin
    case Req.post("http://127.0.0.1:4001/api/v1/users",
           json: %{
             username: username, password: password, role: "ca_admin",
             display_name: "#{tenant.name} CA Admin", ca_instance_id: "default",
             must_change_password: true,
             credential_expires_at: DateTime.to_iso8601(expires_at)
           },
           headers: [{"x-internal-secret", secret}], retry: false
         ) do
      {:ok, %{status: s}} when s in 200..299 -> []
      {:ok, %{status: s}} -> ["CA admin reset failed (HTTP #{s})"]
      {:error, reason} -> ["CA admin reset failed: #{inspect(reason)}"]
    end
  end

  defp delete_and_recreate_admin(:ra, username, password, tenant, secret, expires_at) do
    # Delete existing RA admin
    case Req.get("http://127.0.0.1:4003/api/v1/users",
           headers: [{"x-internal-secret", secret}],
           params: [role: "ra_admin", tenant_id: tenant.id],
           retry: false
         ) do
      {:ok, %{status: 200, body: users}} when is_list(users) ->
        for user <- users, user["username"] == username do
          Req.delete("http://127.0.0.1:4003/api/v1/users/#{user["id"]}",
            headers: [{"x-internal-secret", secret}], retry: false)
        end
      _ -> :ok
    end

    # Create new RA admin
    case Req.post("http://127.0.0.1:4003/api/v1/users",
           json: %{
             username: username, password: password, role: "ra_admin",
             display_name: "#{tenant.name} RA Admin", tenant_id: tenant.id,
             must_change_password: true,
             credential_expires_at: DateTime.to_iso8601(expires_at)
           },
           headers: [{"x-internal-secret", secret}], retry: false
         ) do
      {:ok, %{status: s}} when s in 200..299 -> []
      {:ok, %{status: s}} -> ["RA admin reset failed (HTTP #{s})"]
      {:error, reason} -> ["RA admin reset failed: #{inspect(reason)}"]
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div id="tenant-detail" class="space-y-6">
      <%!-- Back link --%>
      <div>
        <.link navigate="/tenants" class="inline-flex items-center gap-1.5 text-sm text-base-content/60 hover:text-base-content transition-colors">
          <.icon name="hero-arrow-left" class="size-4" />
          Back to Tenants
        </.link>
      </div>

      <%!-- Tenant info card --%>
      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-5">
          <div class="flex items-start justify-between gap-4">
            <div class="flex items-center gap-3">
              <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-primary/10">
                <.icon name="hero-building-office-2" class="size-5 text-primary" />
              </div>
              <div>
                <h2 class="text-xl font-bold text-base-content">{@tenant.name}</h2>
                <span class={[
                  "badge badge-sm mt-1",
                  @tenant.status == "active" && "badge-success",
                  @tenant.status == "suspended" && "badge-warning",
                  @tenant.status == "initialized" && "badge-ghost"
                ]}>{@tenant.status}</span>
              </div>
            </div>

            <%!-- Action buttons --%>
            <div class="flex items-center gap-2 flex-shrink-0">
              <button
                :if={@tenant.status in ["initialized", "active"]}
                phx-click="suspend"
                data-confirm={"Are you sure you want to suspend \"#{@tenant.name}\"?"}
                class="btn btn-sm btn-warning btn-outline"
              >
                <.icon name="hero-pause-circle" class="size-4" />
                Suspend
              </button>
              <button
                :if={@tenant.status == "suspended"}
                phx-click="activate"
                class="btn btn-sm btn-success btn-outline"
              >
                <.icon name="hero-play-circle" class="size-4" />
                Activate
              </button>
              <button
                :if={@tenant.status == "suspended"}
                phx-click="delete"
                data-confirm={"This will permanently delete \"#{@tenant.name}\" and its database. This action cannot be undone. Continue?"}
                class="btn btn-sm btn-error btn-outline"
              >
                <.icon name="hero-trash" class="size-4" />
                Delete
              </button>
            </div>
          </div>

          <%!-- Tenant details grid --%>
          <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mt-5 pt-5 border-t border-base-300">
            <div>
              <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider mb-1">Slug</p>
              <p class="font-mono text-sm font-medium">{@tenant.slug}</p>
            </div>
            <div>
              <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider mb-1">Signing Algorithm</p>
              <p class="font-mono text-sm font-medium">{@tenant.signing_algorithm}</p>
            </div>
            <div>
              <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider mb-1">Database</p>
              <p class="font-mono text-sm font-medium truncate" title={@tenant.database_name}>{@tenant.database_name}</p>
            </div>
            <div>
              <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider mb-1">Created</p>
              <p class="text-sm font-medium">{Calendar.strftime(@tenant.inserted_at, "%Y-%m-%d")}</p>
            </div>
          </div>
        </div>
      </div>

      <%!-- Admin setup status --%>
      <div>
        <div class="flex items-center justify-between mb-3">
          <h3 class="text-sm font-semibold text-base-content">Admin Setup Status</h3>
          <button
            :if={@tenant.status == "active" && @tenant.email}
            phx-click="resend_credentials"
            data-confirm="This will reset ALL admin passwords and send new credentials. Continue?"
            class="btn btn-ghost btn-xs text-primary"
            phx-disable-with="Sending..."
          >
            <.icon name="hero-envelope" class="size-3.5" />
            Resend All Credentials
          </button>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <%!-- CA Admin --%>
          <div class="card bg-base-100 shadow-sm border border-base-300">
            <div class="card-body p-5">
              <div class="flex items-center justify-between mb-3">
                <div class="flex items-center gap-2">
                  <div class="flex items-center justify-center w-8 h-8 rounded-lg bg-primary/10">
                    <.icon name="hero-shield-check" class="size-4 text-primary" />
                  </div>
                  <h4 class="text-sm font-semibold">CA Admin</h4>
                </div>
                <span :if={@metrics.ca_users > 0} class="badge badge-sm badge-success">Configured</span>
                <span :if={@metrics.ca_users == 0} class="badge badge-sm badge-warning">Pending</span>
              </div>
              <p :if={@metrics.ca_users > 0} class="text-sm text-base-content/60">
                {@metrics.ca_users} user{if @metrics.ca_users != 1, do: "s", else: ""} configured.
              </p>
              <div :if={@metrics.ca_users == 0 && @tenant.status != "active"} class="text-xs text-base-content/50">
                Activate the tenant first, then admin credentials will be provisioned.
              </div>
              <div class="flex gap-2 mt-3">
                <button
                  :if={@tenant.status == "active" && @tenant.email}
                  phx-click="reset_ca_admin"
                  data-confirm="This will delete the existing CA admin and create a new one with a temporary password. Continue?"
                  class="btn btn-ghost btn-xs text-warning"
                  phx-disable-with="Resetting..."
                >
                  <.icon name="hero-arrow-path" class="size-3.5" />
                  Reset CA Admin
                </button>
              </div>
            </div>
          </div>

          <%!-- RA Admin --%>
          <div class="card bg-base-100 shadow-sm border border-base-300">
            <div class="card-body p-5">
              <div class="flex items-center justify-between mb-3">
                <div class="flex items-center gap-2">
                  <div class="flex items-center justify-center w-8 h-8 rounded-lg bg-secondary/10">
                    <.icon name="hero-clipboard-document-check" class="size-4 text-secondary" />
                  </div>
                  <h4 class="text-sm font-semibold">RA Admin</h4>
                </div>
                <span :if={@metrics.ra_users > 0} class="badge badge-sm badge-success">Configured</span>
                <span :if={@metrics.ra_users == 0} class="badge badge-sm badge-warning">Pending</span>
              </div>
              <p :if={@metrics.ra_users > 0} class="text-sm text-base-content/60">
                {@metrics.ra_users} user{if @metrics.ra_users != 1, do: "s", else: ""} configured.
              </p>
              <div :if={@metrics.ra_users == 0 && @tenant.status != "active"} class="text-xs text-base-content/50">
                Activate the tenant first, then admin credentials will be provisioned.
              </div>
              <div class="flex gap-2 mt-3">
                <button
                  :if={@tenant.status == "active" && @tenant.email}
                  phx-click="reset_ra_admin"
                  data-confirm="This will delete the existing RA admin and create a new one with a temporary password. Continue?"
                  class="btn btn-ghost btn-xs text-warning"
                  phx-disable-with="Resetting..."
                >
                  <.icon name="hero-arrow-path" class="size-3.5" />
                  Reset RA Admin
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <%!-- Health metrics --%>
      <div>
        <h3 class="text-sm font-semibold text-base-content mb-3">Health Metrics</h3>
        <div class="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-4 gap-4">
          <div class="card bg-base-100 shadow-sm border border-base-300">
            <div class="card-body p-4">
              <div class="flex items-center justify-center w-8 h-8 rounded-lg bg-info/10 mb-2">
                <.icon name="hero-circle-stack" class="size-4 text-info" />
              </div>
              <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider">DB Size</p>
              <p class="text-lg font-bold mt-0.5">{PkiPlatformEngine.TenantMetrics.format_bytes(@metrics.db_size)}</p>
            </div>
          </div>

          <div class="card bg-base-100 shadow-sm border border-base-300">
            <div class="card-body p-4">
              <div class="flex items-center justify-center w-8 h-8 rounded-lg bg-primary/10 mb-2">
                <.icon name="hero-shield-check" class="size-4 text-primary" />
              </div>
              <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider">CA Users</p>
              <p class="text-lg font-bold mt-0.5">{@metrics.ca_users}</p>
            </div>
          </div>

          <div class="card bg-base-100 shadow-sm border border-base-300">
            <div class="card-body p-4">
              <div class="flex items-center justify-center w-8 h-8 rounded-lg bg-secondary/10 mb-2">
                <.icon name="hero-clipboard-document-check" class="size-4 text-secondary" />
              </div>
              <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider">RA Users</p>
              <p class="text-lg font-bold mt-0.5">{@metrics.ra_users}</p>
            </div>
          </div>

          <div class="card bg-base-100 shadow-sm border border-base-300">
            <div class="card-body p-4">
              <div class="flex items-center justify-center w-8 h-8 rounded-lg bg-success/10 mb-2">
                <.icon name="hero-document-check" class="size-4 text-success" />
              </div>
              <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider">Certs Issued</p>
              <p class="text-lg font-bold mt-0.5">{@metrics.certificates_issued}</p>
            </div>
          </div>

          <div class="card bg-base-100 shadow-sm border border-base-300">
            <div class="card-body p-4">
              <div class="flex items-center justify-center w-8 h-8 rounded-lg bg-success/10 mb-2">
                <.icon name="hero-check-badge" class="size-4 text-success" />
              </div>
              <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider">Active Certs</p>
              <p class="text-lg font-bold mt-0.5">{@metrics.active_certificates}</p>
            </div>
          </div>

          <div class="card bg-base-100 shadow-sm border border-base-300">
            <div class="card-body p-4">
              <div class="flex items-center justify-center w-8 h-8 rounded-lg bg-warning/10 mb-2">
                <.icon name="hero-clock" class="size-4 text-warning" />
              </div>
              <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider">Pending CSRs</p>
              <p class="text-lg font-bold mt-0.5">{@metrics.pending_csrs}</p>
            </div>
          </div>

          <div class="card bg-base-100 shadow-sm border border-base-300">
            <div class="card-body p-4">
              <div class="flex items-center justify-center w-8 h-8 rounded-lg bg-primary/10 mb-2">
                <.icon name="hero-server-stack" class="size-4 text-primary" />
              </div>
              <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider">CA Instances</p>
              <p class="text-lg font-bold mt-0.5">{@metrics.ca_instances}</p>
            </div>
          </div>

          <div class="card bg-base-100 shadow-sm border border-base-300">
            <div class="card-body p-4">
              <div class="flex items-center justify-center w-8 h-8 rounded-lg bg-secondary/10 mb-2">
                <.icon name="hero-server" class="size-4 text-secondary" />
              </div>
              <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider">RA Instances</p>
              <p class="text-lg font-bold mt-0.5">{@metrics.ra_instances}</p>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
  end
end
