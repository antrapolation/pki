defmodule PkiPlatformPortalWeb.TenantDetailLive do
  use PkiPlatformPortalWeb, :live_view

  @impl true
  def mount(%{"id" => id}, _session, socket) do
    case PkiPlatformEngine.Provisioner.get_tenant(id) do
      nil ->
        {:ok,
         socket
         |> put_flash(:error, "Tenant not found.")
         |> push_navigate(to: "/tenants")}

      tenant ->
        metrics = load_metrics(tenant)
        ca_host = System.get_env("CA_PORTAL_HOST", "ca.straptrust.com")
        ra_host = System.get_env("RA_PORTAL_HOST", "ra.straptrust.com")
        ca_setup_url = "https://#{ca_host}/setup?tenant=#{tenant.slug}"
        ra_setup_url = "https://#{ra_host}/setup?tenant=#{tenant.slug}"

        {:ok,
         assign(socket,
           page_title: "Tenant Detail",
           tenant: tenant,
           metrics: metrics,
           ca_setup_url: ca_setup_url,
           ra_setup_url: ra_setup_url
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

  defp load_metrics(tenant) do
    PkiPlatformEngine.TenantMetrics.get_metrics(tenant)
  rescue
    _ -> %{db_size: 0, ca_users: 0, ra_users: 0, certificates_issued: 0, active_certificates: 0, pending_csrs: 0}
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
        <h3 class="text-sm font-semibold text-base-content mb-3">Admin Setup Status</h3>
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
                <span :if={@metrics.ca_users == 0} class="badge badge-sm badge-warning">Pending setup</span>
              </div>
              <p :if={@metrics.ca_users > 0} class="text-sm text-base-content/60">
                {@metrics.ca_users} admin user{if @metrics.ca_users != 1, do: "s", else: ""} configured.
              </p>
              <div :if={@metrics.ca_users == 0} class="space-y-2">
                <p class="text-xs text-base-content/60">No CA admin configured. Use the setup URL below:</p>
                <div class="flex items-center gap-2 bg-base-200 rounded-lg px-3 py-2">
                  <.icon name="hero-link" class="size-3.5 text-base-content/40 flex-shrink-0" />
                  <a href={@ca_setup_url} target="_blank" class="font-mono text-xs text-primary hover:underline truncate">{@ca_setup_url}</a>
                </div>
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
                <span :if={@metrics.ra_users == 0} class="badge badge-sm badge-warning">Pending setup</span>
              </div>
              <p :if={@metrics.ra_users > 0} class="text-sm text-base-content/60">
                {@metrics.ra_users} admin user{if @metrics.ra_users != 1, do: "s", else: ""} configured.
              </p>
              <div :if={@metrics.ra_users == 0} class="space-y-2">
                <p class="text-xs text-base-content/60">No RA admin configured. Use the setup URL below:</p>
                <div class="flex items-center gap-2 bg-base-200 rounded-lg px-3 py-2">
                  <.icon name="hero-link" class="size-3.5 text-base-content/40 flex-shrink-0" />
                  <a href={@ra_setup_url} target="_blank" class="font-mono text-xs text-primary hover:underline truncate">{@ra_setup_url}</a>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <%!-- Health metrics --%>
      <div>
        <h3 class="text-sm font-semibold text-base-content mb-3">Health Metrics</h3>
        <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
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
        </div>
      </div>
    </div>
    """
  end
end
