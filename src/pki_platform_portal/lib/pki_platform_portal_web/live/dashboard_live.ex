defmodule PkiPlatformPortalWeb.DashboardLive do
  use PkiPlatformPortalWeb, :live_view

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_data)

    {:ok,
     assign(socket,
       page_title: "Dashboard",
       total_tenants: 0,
       active_tenants: 0,
       suspended_tenants: 0,
       initialized_tenants: 0,
       healthy_services: 0,
       total_services: 6,
       recent_tenants: [],
       loading: true
     )}
  end

  @impl true
  def handle_info(:load_data, socket) do
    tenants = list_tenants()
    active = Enum.count(tenants, &(&1.status == "active"))
    suspended = Enum.count(tenants, &(&1.status == "suspended"))
    initialized = Enum.count(tenants, &(&1.status == "initialized"))

    send(self(), :check_services)

    {:noreply,
     assign(socket,
       total_tenants: length(tenants),
       active_tenants: active,
       suspended_tenants: suspended,
       initialized_tenants: initialized,
       recent_tenants: Enum.take(tenants, 5),
       loading: false
     )}
  end

  @impl true
  def handle_info(:check_services, socket) do
    services = PkiPlatformEngine.SystemHealth.check_all()
    healthy_services = Enum.count(services, &(&1.status == :healthy))
    total_services = length(services)

    {:noreply,
     assign(socket,
       healthy_services: healthy_services,
       total_services: total_services
     )}
  end

  defp list_tenants do
    PkiPlatformEngine.Provisioner.list_tenants()
  rescue
    _ -> []
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div id="dashboard" class="space-y-6">
      <%!-- Stat cards — top row --%>
      <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-5">
            <div class="flex items-center gap-3">
              <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-primary/10">
                <.icon name="hero-building-office-2" class="size-5 text-primary" />
              </div>
              <div>
                <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider">Total Tenants</p>
                <p class="text-xl font-bold">{@total_tenants}</p>
              </div>
            </div>
          </div>
        </div>

        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-5">
            <div class="flex items-center gap-3">
              <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-success/10">
                <.icon name="hero-check-circle" class="size-5 text-success" />
              </div>
              <div>
                <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider">Active</p>
                <p class="text-xl font-bold">{@active_tenants}</p>
              </div>
            </div>
          </div>
        </div>

        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-5">
            <div class="flex items-center gap-3">
              <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-warning/10">
                <.icon name="hero-pause-circle" class="size-5 text-warning" />
              </div>
              <div>
                <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider">Suspended</p>
                <p class="text-xl font-bold">{@suspended_tenants}</p>
              </div>
            </div>
          </div>
        </div>

        <.link navigate="/tenants" class="card bg-primary/5 shadow-sm border border-primary/20 hover:bg-primary/10 transition-colors cursor-pointer">
          <div class="card-body p-5">
            <div class="flex items-center gap-3">
              <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-primary/10">
                <.icon name="hero-plus-circle" class="size-5 text-primary" />
              </div>
              <div>
                <p class="text-xs font-medium text-primary/70 uppercase tracking-wider">Quick Action</p>
                <p class="text-sm font-semibold text-primary">Create Tenant</p>
              </div>
            </div>
          </div>
        </.link>
      </div>

      <%!-- Stat cards — second row --%>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-5">
            <div class="flex items-center gap-3">
              <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-info/10">
                <.icon name="hero-clock" class="size-5 text-info" />
              </div>
              <div>
                <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider">Pending Setup</p>
                <p class="text-xl font-bold">{@initialized_tenants}</p>
              </div>
            </div>
          </div>
        </div>

        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-5">
            <div class="flex items-center gap-3">
              <div class={[
                "flex items-center justify-center w-10 h-10 rounded-lg",
                @healthy_services == @total_services && "bg-success/10",
                @healthy_services != @total_services && "bg-warning/10"
              ]}>
                <.icon
                  name="hero-server-stack"
                  class={[
                    "size-5",
                    @healthy_services == @total_services && "text-success",
                    @healthy_services != @total_services && "text-warning"
                  ]}
                />
              </div>
              <div>
                <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider">Services</p>
                <p class="text-xl font-bold">{@healthy_services}/{@total_services}</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      <%!-- Recent Tenants --%>
      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-0">
          <div class="px-5 py-4 border-b border-base-300 flex items-center justify-between">
            <h2 class="text-sm font-semibold text-base-content">Recent Tenants</h2>
            <.link navigate="/tenants" class="text-xs text-primary hover:underline">View all</.link>
          </div>
          <div class="overflow-x-auto">
            <table class="table table-sm w-full">
              <thead>
                <tr class="text-xs uppercase text-base-content/50">
                  <th class="w-1/5">Name</th>
                  <th class="w-1/6">Slug</th>
                  <th class="w-[80px]">Status</th>
                  <th class="w-1/5">Email</th>
                  <th class="w-[120px]">Created</th>
                </tr>
              </thead>
              <tbody>
                <tr :if={@recent_tenants == []}>
                  <td colspan="5" class="text-center text-base-content/50 py-8">
                    No tenants yet.
                    <.link navigate="/tenants" class="text-primary hover:underline">Create your first tenant</.link>
                  </td>
                </tr>
                <tr :for={tenant <- @recent_tenants} class="hover cursor-pointer">
                  <td class="font-medium truncate max-w-[150px]">{tenant.name}</td>
                  <td class="font-mono text-sm truncate max-w-[120px]">{tenant.slug}</td>
                  <td>
                    <span class={[
                      "badge badge-sm",
                      tenant.status == "active" && "badge-success",
                      tenant.status == "suspended" && "badge-warning",
                      tenant.status == "initialized" && "badge-ghost"
                    ]}>{tenant.status}</span>
                  </td>
                  <td class="font-mono text-sm truncate max-w-[150px]">{tenant.email}</td>
                  <td class="text-base-content/60 text-sm">{Calendar.strftime(tenant.inserted_at, "%Y-%m-%d")}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
    """
  end
end
