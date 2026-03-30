defmodule PkiCaPortalWeb.DashboardLive do
  use PkiCaPortalWeb, :live_view

  alias PkiCaPortal.CaEngineClient

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_data)

    {:ok,
     assign(socket,
       page_title: "Dashboard",
       engine_status: %{status: "unknown", uptime_seconds: 0, active_keys: 0},
       active_keys: [],
       recent_ceremonies: [],
       loading: true,
       page: 1,
       per_page: 10
     )}
  end

  @impl true
  def handle_info(:load_data, socket) do
    ca_id = socket.assigns.current_user[:ca_instance_id] || "default"
    opts = tenant_opts(socket)

    status =
      case CaEngineClient.get_engine_status(ca_id, opts) do
        {:ok, s} -> s
        {:error, _} -> %{status: "unknown", uptime_seconds: 0, active_keys: 0}
      end

    keys =
      case CaEngineClient.list_issuer_keys(ca_id, opts) do
        {:ok, k} -> k
        {:error, _} -> []
      end

    ceremonies =
      case CaEngineClient.list_ceremonies(ca_id, opts) do
        {:ok, c} -> c
        {:error, _} -> []
      end

    {:noreply,
     assign(socket,
       engine_status: status,
       active_keys: keys,
       recent_ceremonies: ceremonies,
       loading: false
     )}
  end

  @impl true
  def handle_event("change_page", %{"page" => page}, socket) do
    {:noreply, assign(socket, page: String.to_integer(page))}
  end

  defp tenant_opts(socket) do
    case socket.assigns[:tenant_id] do
      nil -> []
      tid -> [tenant_id: tid]
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div id="dashboard" class="space-y-6">
      <%!-- Stat cards row --%>
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div id="status-card" class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-5">
            <div class="flex items-center gap-3">
              <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-success/10">
                <.icon name="hero-signal" class="size-5 text-success" />
              </div>
              <div>
                <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider">Engine Status</p>
                <p class="text-xl font-bold">
                  <span id="engine-status">{@engine_status.status}</span>
                </p>
              </div>
            </div>
            <p class="text-xs text-base-content/40 mt-2">Uptime: {@engine_status.uptime_seconds}s</p>
          </div>
        </div>

        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-5">
            <div class="flex items-center gap-3">
              <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-primary/10">
                <.icon name="hero-key" class="size-5 text-primary" />
              </div>
              <div>
                <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider">Active Keys</p>
                <p class="text-xl font-bold">
                  <span id="active-key-count">{@engine_status.active_keys}</span>
                </p>
              </div>
            </div>
          </div>
        </div>

        <div id="key-summary" class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-5">
            <div class="flex items-center gap-3">
              <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-info/10">
                <.icon name="hero-circle-stack" class="size-5 text-info" />
              </div>
              <div>
                <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider">Total Keys</p>
                <p class="text-xl font-bold">
                  <span id="key-count">{length(@active_keys)}</span>
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      <%!-- Recent Ceremonies --%>
      <% paginated_ceremonies = @recent_ceremonies |> Enum.drop((@page - 1) * @per_page) |> Enum.take(@per_page) %>
      <% total_ceremonies = length(@recent_ceremonies) %>
      <% total_pages = max(ceil(total_ceremonies / @per_page), 1) %>
      <% start_idx = min((@page - 1) * @per_page + 1, total_ceremonies) %>
      <% end_idx = min(@page * @per_page, total_ceremonies) %>
      <div id="recent-ceremonies" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-0">
          <div class="px-5 py-4 border-b border-base-300">
            <h2 class="text-sm font-semibold text-base-content">Recent Ceremonies</h2>
          </div>
          <div class="overflow-x-auto">
            <table class="table table-sm">
              <thead>
                <tr class="text-xs uppercase text-base-content/50">
                  <th>ID</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Algorithm</th>
                </tr>
              </thead>
              <tbody>
                <tr :for={ceremony <- paginated_ceremonies} class="hover">
                  <td class="font-mono-data">{ceremony.id}</td>
                  <td>{ceremony.ceremony_type}</td>
                  <td>
                    <span class="badge badge-sm badge-ghost">{ceremony.status}</span>
                  </td>
                  <td class="font-mono-data">{ceremony.algorithm}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div :if={total_ceremonies > 0} class="flex items-center justify-between px-5 py-3 border-t border-base-300 text-sm">
            <span class="text-base-content/60">
              Showing {start_idx}–{end_idx} of {total_ceremonies}
            </span>
            <div class="join">
              <button class="join-item btn btn-sm" phx-click="change_page" phx-value-page={@page - 1} disabled={@page == 1}>«</button>
              <button class="join-item btn btn-sm btn-active">{@page}</button>
              <button class="join-item btn btn-sm" phx-click="change_page" phx-value-page={@page + 1} disabled={@page >= total_pages}>»</button>
            </div>
          </div>
        </div>
      </div>

      <%!-- Quick Actions --%>
      <div id="quick-actions">
        <h2 class="text-sm font-semibold text-base-content mb-3">Quick Actions</h2>
        <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
          <a href="/ceremony" class="card bg-base-100 border border-base-300 hover:border-primary/40 transition-colors cursor-pointer">
            <div class="card-body items-center p-4 text-center">
              <.icon name="hero-shield-check" class="size-6 text-primary mb-1" />
              <span class="text-sm font-medium">Initiate Ceremony</span>
            </div>
          </a>
          <a href="/users" class="card bg-base-100 border border-base-300 hover:border-primary/40 transition-colors cursor-pointer">
            <div class="card-body items-center p-4 text-center">
              <.icon name="hero-users" class="size-6 text-primary mb-1" />
              <span class="text-sm font-medium">Manage Users</span>
            </div>
          </a>
          <a href="/keystores" class="card bg-base-100 border border-base-300 hover:border-primary/40 transition-colors cursor-pointer">
            <div class="card-body items-center p-4 text-center">
              <.icon name="hero-key" class="size-6 text-primary mb-1" />
              <span class="text-sm font-medium">Manage Keystores</span>
            </div>
          </a>
          <a href="/audit-log" class="card bg-base-100 border border-base-300 hover:border-primary/40 transition-colors cursor-pointer">
            <div class="card-body items-center p-4 text-center">
              <.icon name="hero-document-text" class="size-6 text-primary mb-1" />
              <span class="text-sm font-medium">View Audit Log</span>
            </div>
          </a>
        </div>
      </div>
    </div>
    """
  end
end
