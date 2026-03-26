defmodule PkiRaPortalWeb.DashboardLive do
  use PkiRaPortalWeb, :live_view

  alias PkiRaPortal.RaEngineClient

  @impl true
  def mount(_params, _session, socket) do
    {:ok, csrs} = RaEngineClient.list_csrs()
    {:ok, profiles} = RaEngineClient.list_cert_profiles()

    pending_csrs = Enum.filter(csrs, &(&1.status == "pending"))
    recent_csrs = Enum.take(csrs, 5)

    {:ok,
     assign(socket,
       page_title: "Dashboard",
       pending_csr_count: length(pending_csrs),
       recent_csrs: recent_csrs,
       cert_profile_count: length(profiles),
       page: 1,
       per_page: 10
     )}
  end

  @impl true
  def handle_event("change_page", %{"page" => page}, socket) do
    {:noreply, assign(socket, page: String.to_integer(page))}
  end

  @impl true
  def render(assigns) do
    total = length(assigns.recent_csrs)
    total_pages = max(ceil(total / assigns.per_page), 1)
    start_idx = (assigns.page - 1) * assigns.per_page
    paged_csrs = assigns.recent_csrs |> Enum.drop(start_idx) |> Enum.take(assigns.per_page)

    assigns =
      assigns
      |> Map.put(:paged_csrs, paged_csrs)
      |> Map.put(:total_pages, total_pages)

    ~H"""
    <div id="dashboard" class="space-y-6">
      <h1 class="text-2xl font-bold tracking-tight">Dashboard</h1>

      <%!-- Stat Cards --%>
      <section id="status-card" class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <h2 class="md:col-span-2 text-sm font-semibold uppercase tracking-wide text-base-content/60">RA Overview</h2>
        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body">
            <div class="flex items-center gap-3">
              <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-warning/10">
                <.icon name="hero-document-check" class="size-6 text-warning" />
              </div>
              <div>
                <p class="text-xs font-medium text-base-content/60 uppercase tracking-wide">Pending CSRs</p>
                <p class="text-2xl font-bold" id="pending-csr-count">{@pending_csr_count}</p>
              </div>
            </div>
          </div>
        </div>

        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body">
            <div class="flex items-center gap-3">
              <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-primary/10">
                <.icon name="hero-clipboard-document-list" class="size-6 text-primary" />
              </div>
              <div>
                <p class="text-xs font-medium text-base-content/60 uppercase tracking-wide">Certificate Profiles</p>
                <p class="text-2xl font-bold" id="cert-profile-count">{@cert_profile_count}</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      <%!-- Recent CSRs --%>
      <section id="recent-csrs" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <h2 class="card-title text-sm font-semibold uppercase tracking-wide text-base-content/60">Recent CSRs</h2>
          <div class="overflow-x-auto">
            <table class="table table-sm">
              <thead>
                <tr class="border-base-300">
                  <th class="font-semibold text-xs uppercase tracking-wider">ID</th>
                  <th class="font-semibold text-xs uppercase tracking-wider">Subject</th>
                  <th class="font-semibold text-xs uppercase tracking-wider">Profile</th>
                  <th class="font-semibold text-xs uppercase tracking-wider">Status</th>
                </tr>
              </thead>
              <tbody>
                <tr :for={csr <- @paged_csrs} class="hover:bg-base-200/50 border-base-300">
                  <td class="font-mono text-xs">{csr.id}</td>
                  <td>{csr.subject}</td>
                  <td>{csr.profile_name}</td>
                  <td>
                    <span class={[
                      "badge badge-sm",
                      csr.status == "pending" && "badge-warning",
                      csr.status == "approved" && "badge-success",
                      csr.status == "rejected" && "badge-error"
                    ]}>
                      {csr.status}
                    </span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <div :if={@total_pages > 1} class="flex justify-center mt-4">
            <div class="join">
              <button
                :for={p <- 1..@total_pages}
                phx-click="change_page"
                phx-value-page={p}
                class={["join-item btn btn-sm", p == @page && "btn-active"]}
              >
                {p}
              </button>
            </div>
          </div>
        </div>
      </section>

      <%!-- Quick Actions --%>
      <section id="quick-actions">
        <h2 class="text-sm font-semibold text-base-content mb-3">Quick Actions</h2>
        <div class="grid grid-cols-2 md:grid-cols-5 gap-3">
          <a href="/csrs" class="card bg-base-100 border border-base-300 hover:border-primary/40 transition-colors cursor-pointer">
            <div class="card-body items-center p-4 text-center">
              <.icon name="hero-document-check" class="size-6 text-primary mb-1" />
              <span class="text-sm font-medium">Manage CSRs</span>
            </div>
          </a>
          <a href="/users" class="card bg-base-100 border border-base-300 hover:border-primary/40 transition-colors cursor-pointer">
            <div class="card-body items-center p-4 text-center">
              <.icon name="hero-users" class="size-6 text-primary mb-1" />
              <span class="text-sm font-medium">Manage Users</span>
            </div>
          </a>
          <a href="/cert-profiles" class="card bg-base-100 border border-base-300 hover:border-primary/40 transition-colors cursor-pointer">
            <div class="card-body items-center p-4 text-center">
              <.icon name="hero-clipboard-document-list" class="size-6 text-primary mb-1" />
              <span class="text-sm font-medium">Cert Profiles</span>
            </div>
          </a>
          <a href="/service-configs" class="card bg-base-100 border border-base-300 hover:border-primary/40 transition-colors cursor-pointer">
            <div class="card-body items-center p-4 text-center">
              <.icon name="hero-cog-6-tooth" class="size-6 text-primary mb-1" />
              <span class="text-sm font-medium">Service Configs</span>
            </div>
          </a>
          <a href="/api-keys" class="card bg-base-100 border border-base-300 hover:border-primary/40 transition-colors cursor-pointer">
            <div class="card-body items-center p-4 text-center">
              <.icon name="hero-key" class="size-6 text-primary mb-1" />
              <span class="text-sm font-medium">API Keys</span>
            </div>
          </a>
        </div>
      </section>
    </div>
    """
  end
end
