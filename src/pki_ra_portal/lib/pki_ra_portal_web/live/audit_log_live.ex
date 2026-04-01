defmodule PkiRaPortalWeb.AuditLogLive do
  use PkiRaPortalWeb, :live_view

  alias PkiRaPortal.RaEngineClient

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_data)

    {:ok,
     assign(socket,
       page_title: "Audit Log",
       events: [],
       loading: true,
       filter_action: "",
       filter_actor: "",
       filter_date_from: "",
       filter_date_to: "",
       page: 1,
       per_page: 10
     )}
  end

  @impl true
  def handle_info(:load_data, socket) do
    opts = tenant_opts(socket)

    events =
      case RaEngineClient.list_audit_events([], opts) do
        {:ok, events} -> events
        {:error, _} -> []
      end

    {:noreply, assign(socket, events: events, loading: false)}
  end

  @impl true
  def handle_event("filter", params, socket) do
    filters =
      []
      |> maybe_add(:action, params["action"])
      |> maybe_add(:actor_username, params["actor"])
      |> maybe_add(:date_from, params["date_from"])
      |> maybe_add(:date_to, params["date_to"])

    events =
      case RaEngineClient.list_audit_events(filters, tenant_opts(socket)) do
        {:ok, events} -> events
        {:error, _} -> []
      end

    {:noreply,
     assign(socket,
       events: events,
       filter_action: params["action"] || "",
       filter_actor: params["actor"] || "",
       filter_date_from: params["date_from"] || "",
       filter_date_to: params["date_to"] || "",
       page: 1
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

  defp maybe_add(filters, _key, nil), do: filters
  defp maybe_add(filters, _key, ""), do: filters
  defp maybe_add(filters, key, value), do: [{key, value} | filters]

  @impl true
  def render(assigns) do
    ~H"""
    <div id="audit-log-page" class="space-y-6">
      <%!-- Filter form --%>
      <div id="audit-filter" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-4">
          <form phx-submit="filter" class="flex flex-wrap items-end gap-3">
            <div>
              <label for="action" class="block text-xs font-medium text-base-content/60 mb-1">Action</label>
              <select name="action" id="filter-action" class="select select-bordered select-sm">
                <option value="">All</option>
                <option value="login" selected={@filter_action == "login"}>Login</option>
                <option value="login_failed" selected={@filter_action == "login_failed"}>Login Failed</option>
                <option value="user_created" selected={@filter_action == "user_created"}>User Created</option>
                <option value="user_suspended" selected={@filter_action == "user_suspended"}>User Suspended</option>
                <option value="user_activated" selected={@filter_action == "user_activated"}>User Activated</option>
                <option value="user_deleted" selected={@filter_action == "user_deleted"}>User Deleted</option>
                <option value="password_reset" selected={@filter_action == "password_reset"}>Password Reset</option>
                <option value="password_changed" selected={@filter_action == "password_changed"}>Password Changed</option>
                <option value="profile_updated" selected={@filter_action == "profile_updated"}>Profile Updated</option>
              </select>
            </div>
            <div>
              <label for="actor" class="block text-xs font-medium text-base-content/60 mb-1">Actor</label>
              <input type="text" name="actor" id="filter-actor" value={@filter_actor} class="input input-bordered input-sm w-40" placeholder="Search actor..." />
            </div>
            <div>
              <label for="date_from" class="block text-xs font-medium text-base-content/60 mb-1">From</label>
              <input type="date" name="date_from" id="filter-date-from" value={@filter_date_from} class="input input-bordered input-sm" />
            </div>
            <div>
              <label for="date_to" class="block text-xs font-medium text-base-content/60 mb-1">To</label>
              <input type="date" name="date_to" id="filter-date-to" value={@filter_date_to} class="input input-bordered input-sm" />
            </div>
            <div>
              <button type="submit" class="btn btn-primary btn-sm">
                <.icon name="hero-funnel" class="size-4" />
                Apply Filter
              </button>
            </div>
          </form>
        </div>
      </div>

      <%!-- Events table --%>
      <% paginated = @events |> Enum.drop((@page - 1) * @per_page) |> Enum.take(@per_page) %>
      <% total = length(@events) %>
      <% total_pages = max(ceil(total / @per_page), 1) %>
      <% start_idx = min((@page - 1) * @per_page + 1, total) %>
      <% end_idx = min(@page * @per_page, total) %>
      <div id="audit-table" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-0">
          <div class="overflow-x-auto">
            <table class="table table-sm">
              <thead>
                <tr class="text-xs uppercase text-base-content/50">
                  <th>Timestamp</th>
                  <th>Action</th>
                  <th>Actor</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody id="event-list">
                <tr :for={event <- paginated} id={"event-#{event[:id] || event.id}"} class="hover">
                  <td class="font-mono text-xs">{if ts = event[:timestamp] || Map.get(event, :timestamp), do: Calendar.strftime(ts, "%Y-%m-%d %H:%M:%S"), else: "—"}</td>
                  <td><span class="badge badge-sm badge-ghost">{event[:action] || event.action}</span></td>
                  <td>{event[:actor_username] || Map.get(event, :actor_username, "system")}</td>
                  <td class="text-xs text-base-content/60 max-w-xs truncate">{format_details(event[:details] || Map.get(event, :details, %{}))}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div :if={total > 0} class="flex items-center justify-between px-5 py-3 border-t border-base-300 text-sm">
            <span class="text-base-content/60">Showing {start_idx}–{end_idx} of {total}</span>
            <div class="join">
              <button class="join-item btn btn-sm" phx-click="change_page" phx-value-page={@page - 1} disabled={@page == 1}>«</button>
              <button class="join-item btn btn-sm btn-active">{@page}</button>
              <button class="join-item btn btn-sm" phx-click="change_page" phx-value-page={@page + 1} disabled={@page >= total_pages}>»</button>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
  end

  defp format_details(nil), do: ""
  defp format_details(details) when map_size(details) == 0, do: ""
  defp format_details(details) do
    details
    |> Enum.map(fn {k, v} -> "#{k}: #{v}" end)
    |> Enum.join(", ")
  end
end
