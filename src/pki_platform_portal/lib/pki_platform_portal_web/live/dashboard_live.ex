defmodule PkiPlatformPortalWeb.DashboardLive do
  use PkiPlatformPortalWeb, :live_view

  @impl true
  def mount(_params, _session, socket) do
    tenants = list_tenants()
    active = Enum.count(tenants, &(&1.status == "active"))

    {:ok,
     assign(socket,
       page_title: "Dashboard",
       total_tenants: length(tenants),
       active_tenants: active,
       recent_tenants: Enum.take(tenants, 5)
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
      <%!-- Stat cards row --%>
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div id="total-tenants-card" class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-5">
            <div class="flex items-center gap-3">
              <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-primary/10">
                <.icon name="hero-building-office-2" class="size-5 text-primary" />
              </div>
              <div>
                <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider">Total Tenants</p>
                <p class="text-xl font-bold">
                  <span id="total-tenants">{@total_tenants}</span>
                </p>
              </div>
            </div>
          </div>
        </div>

        <div id="active-tenants-card" class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-5">
            <div class="flex items-center gap-3">
              <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-success/10">
                <.icon name="hero-check-circle" class="size-5 text-success" />
              </div>
              <div>
                <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider">Active Tenants</p>
                <p class="text-xl font-bold">
                  <span id="active-tenants">{@active_tenants}</span>
                </p>
              </div>
            </div>
          </div>
        </div>

        <div id="quick-actions-card" class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-5">
            <div class="flex items-center gap-3">
              <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-info/10">
                <.icon name="hero-plus-circle" class="size-5 text-info" />
              </div>
              <div>
                <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider">Quick Actions</p>
                <a href="/tenants" class="text-sm text-primary hover:underline">Manage Tenants</a>
              </div>
            </div>
          </div>
        </div>
      </div>

      <%!-- Recent Tenants --%>
      <div id="recent-tenants" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-0">
          <div class="px-5 py-4 border-b border-base-300">
            <h2 class="text-sm font-semibold text-base-content">Recent Tenants</h2>
          </div>
          <div class="overflow-x-auto">
            <table class="table table-sm">
              <thead>
                <tr class="text-xs uppercase text-base-content/50">
                  <th>Name</th>
                  <th>Slug</th>
                  <th>Status</th>
                  <th>Algorithm</th>
                  <th>Created</th>
                </tr>
              </thead>
              <tbody>
                <tr :if={@recent_tenants == []} >
                  <td colspan="5" class="text-center text-base-content/50 py-8">No tenants yet</td>
                </tr>
                <tr :for={tenant <- @recent_tenants} class="hover">
                  <td class="font-medium">{tenant.name}</td>
                  <td class="font-mono text-sm">{tenant.slug}</td>
                  <td>
                    <span class={[
                      "badge badge-sm",
                      tenant.status == "active" && "badge-success",
                      tenant.status == "suspended" && "badge-warning",
                      tenant.status == "initialized" && "badge-ghost"
                    ]}>{tenant.status}</span>
                  </td>
                  <td class="font-mono text-sm">{tenant.signing_algorithm}</td>
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
