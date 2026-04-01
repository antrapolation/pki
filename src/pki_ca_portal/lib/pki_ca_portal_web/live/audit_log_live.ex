defmodule PkiCaPortalWeb.AuditLogLive do
  use PkiCaPortalWeb, :live_view

  alias PkiCaPortal.CaEngineClient

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_data)

    {:ok,
     assign(socket,
       page_title: "Audit Log",
       events: [],
       ca_instances: [],
       loading: true,
       selected_ca_instance_id: "",
       filter_action: "",
       filter_actor: "",
       filter_date_from: "",
       filter_date_to: "",
       category: "all",
       page: 1,
       per_page: 10
     )}
  end

  @impl true
  def handle_info(:load_data, socket) do
    opts = tenant_opts(socket)
    all_events = load_all_events(opts)

    ca_instances =
      case CaEngineClient.list_ca_instances(opts) do
        {:ok, instances} -> instances
        {:error, _} -> []
      end

    {:noreply,
     assign(socket,
       events: all_events,
       ca_instances: ca_instances,
       loading: false
     )}
  end

  @impl true
  def handle_event("filter_ca_instance", %{"ca_instance_id" => ca_instance_id}, socket) do
    ca_filters = maybe_add_filter([], :ca_instance_id, ca_instance_id)
    all_events = load_all_events(tenant_opts(socket), ca_filters)

    events = case socket.assigns.category do
      "all" -> all_events
      cat -> Enum.filter(all_events, &(&1.category == cat))
    end

    {:noreply,
     assign(socket,
       events: events,
       selected_ca_instance_id: ca_instance_id,
       page: 1
     )}
  end

  @impl true
  def handle_event("filter", params, socket) do
    category = params["category"] || "all"
    ca_filters = maybe_add_filter([], :ca_instance_id, socket.assigns.selected_ca_instance_id)
    all_events = load_all_events(tenant_opts(socket), ca_filters)

    events = case category do
      "all" -> all_events
      cat -> Enum.filter(all_events, &(&1.category == cat))
    end

    actor_filter = params["actor"] || ""
    action_filter = params["action"] || ""

    events = events
      |> filter_by_actor(actor_filter)
      |> filter_by_action(action_filter)

    {:noreply,
     assign(socket,
       events: events,
       filter_action: action_filter,
       filter_actor: actor_filter,
       filter_date_from: params["date_from"] || "",
       filter_date_to: params["date_to"] || "",
       category: category,
       page: 1
     )}
  end

  @impl true
  def handle_event("change_page", %{"page" => page}, socket) do
    {:noreply, assign(socket, page: String.to_integer(page))}
  end

  defp load_all_events(opts, ca_filters \\ []) do
    ca_events =
      case CaEngineClient.query_audit_log(ca_filters, opts) do
        {:ok, events} ->
          Enum.map(events, fn e ->
            %{
              event_id: e[:event_id] || Map.get(e, :event_id),
              timestamp: e[:timestamp] || Map.get(e, :timestamp),
              action: e[:action] || Map.get(e, :action),
              actor: e[:actor_did] || Map.get(e, :actor_did, "system"),
              category: "ca_operations"
            }
          end)
        {:error, _} -> []
      end

    platform_events =
      case CaEngineClient.list_audit_events([], opts) do
        {:ok, events} ->
          Enum.map(events, fn e ->
            %{
              event_id: e[:id] || Map.get(e, :id),
              timestamp: e[:timestamp] || Map.get(e, :timestamp),
              action: e[:action] || Map.get(e, :action),
              actor: e[:actor_username] || Map.get(e, :actor_username, "system"),
              category: "user_management"
            }
          end)
        {:error, _} -> []
      end

    (ca_events ++ platform_events)
    |> Enum.sort_by(& &1[:timestamp], {:desc, DateTime})
  end

  defp filter_by_actor(events, ""), do: events
  defp filter_by_actor(events, actor), do: Enum.filter(events, &String.contains?(to_string(&1.actor), actor))

  defp filter_by_action(events, ""), do: events
  defp filter_by_action(events, action), do: Enum.filter(events, &(to_string(&1.action) == action))

  defp tenant_opts(socket) do
    case socket.assigns[:tenant_id] do
      nil -> []
      tid -> [tenant_id: tid]
    end
  end

  defp maybe_add_filter(filters, _key, nil), do: filters
  defp maybe_add_filter(filters, _key, ""), do: filters
  defp maybe_add_filter(filters, key, value), do: [{key, value} | filters]

  @impl true
  def render(assigns) do
    ~H"""
    <div id="audit-log-page" class="space-y-6">
      <%!-- CA Instance filter --%>
      <div class="flex items-center gap-3">
        <label for="ca-instance-filter" class="text-xs font-medium text-base-content/60">Filter by CA Instance</label>
        <form phx-change="filter_ca_instance">
          <select name="ca_instance_id" id="ca-instance-filter" class="select select-bordered select-sm">
            <option value="">All</option>
            <option
              :for={inst <- @ca_instances}
              value={inst.id}
              selected={@selected_ca_instance_id == inst.id}
            >
              {inst.name}
            </option>
          </select>
        </form>
      </div>

      <%!-- Filter form --%>
      <div id="audit-filter" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-4">
          <form phx-submit="filter" class="flex flex-wrap items-end gap-3">
            <div>
              <label for="category" class="block text-xs font-medium text-base-content/60 mb-1">Category</label>
              <select name="category" id="filter-category" class="select select-bordered select-sm">
                <option value="all" selected={@category == "all"}>All</option>
                <option value="ca_operations" selected={@category == "ca_operations"}>CA Operations</option>
                <option value="user_management" selected={@category == "user_management"}>User Management</option>
              </select>
            </div>
            <div>
              <label for="action" class="block text-xs font-medium text-base-content/60 mb-1">Action</label>
              <select name="action" id="filter-action" class="select select-bordered select-sm">
                <option value="">All</option>
                <option value="login" selected={@filter_action == "login"}>Login</option>
                <option value="key_generated" selected={@filter_action == "key_generated"}>
                  Key Generated
                </option>
                <option value="ceremony_initiated" selected={@filter_action == "ceremony_initiated"}>
                  Ceremony Initiated
                </option>
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
      <% paginated_events = @events |> Enum.drop((@page - 1) * @per_page) |> Enum.take(@per_page) %>
      <% total_events = length(@events) %>
      <% total_pages = max(ceil(total_events / @per_page), 1) %>
      <% start_idx = min((@page - 1) * @per_page + 1, total_events) %>
      <% end_idx = min(@page * @per_page, total_events) %>
      <div id="audit-table" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-0">
          <div class="overflow-x-auto">
            <table class="table table-sm">
              <thead>
                <tr class="text-xs uppercase text-base-content/50">
                  <th>Timestamp</th>
                  <th>Category</th>
                  <th>Action</th>
                  <th>Actor</th>
                  <th>Event ID</th>
                </tr>
              </thead>
              <tbody id="event-list">
                <tr :for={event <- paginated_events} id={"event-#{event.event_id}"} class="hover">
                  <td class="font-mono-data">{if event[:timestamp], do: Calendar.strftime(event.timestamp, "%Y-%m-%d %H:%M:%S"), else: "—"}</td>
                  <td>
                    <span class={["badge badge-sm", if(event.category == "ca_operations", do: "badge-info", else: "badge-secondary")]}>
                      {if event.category == "ca_operations", do: "CA Ops", else: "User Mgmt"}
                    </span>
                  </td>
                  <td>
                    <span class="badge badge-sm badge-ghost">{event.action}</span>
                  </td>
                  <td>{event.actor}</td>
                  <td class="font-mono-data">{event.event_id}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div :if={total_events > 0} class="flex items-center justify-between px-5 py-3 border-t border-base-300 text-sm">
            <span class="text-base-content/60">
              Showing {start_idx}–{end_idx} of {total_events}
            </span>
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
end
