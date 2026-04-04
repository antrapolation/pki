defmodule PkiCaPortalWeb.AuditLogLive do
  use PkiCaPortalWeb, :live_view

  alias PkiCaPortal.CaEngineClient

  @impl true
  def mount(_params, _session, socket) do
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
  def handle_params(params, _uri, socket) do
    if connected?(socket), do: send(self(), {:load_data, params})
    {:noreply, socket}
  end

  @impl true
  def handle_info({:load_data, params}, socket) do
    opts = tenant_opts(socket)

    ca_instances =
      case CaEngineClient.list_ca_instances(opts) do
        {:ok, instances} -> instances
        {:error, _} -> []
      end

    ca_id = params["ca"] || ""
    category = params["category"] || "all"
    action_filter = params["action"] || ""
    actor_filter = params["actor"] || ""
    date_from = params["date_from"] || ""
    date_to = params["date_to"] || ""

    ca_filters = if ca_id != "", do: maybe_add_filter([], :ca_instance_id, ca_id), else: []
    all_events = load_all_events(opts, ca_filters)

    events = case category do
      "all" -> all_events
      cat -> Enum.filter(all_events, &(&1.category == cat))
    end

    events = events
      |> filter_by_actor(actor_filter)
      |> filter_by_action(action_filter)

    {:noreply,
     assign(socket,
       events: events,
       ca_instances: ca_instances,
       selected_ca_instance_id: ca_id,
       category: category,
       filter_action: action_filter,
       filter_actor: actor_filter,
       filter_date_from: date_from,
       filter_date_to: date_to,
       loading: false,
       page: 1
     )}
  end

  @impl true
  def handle_event("apply_filter", params, socket) do
    query = URI.encode_query(
      Enum.reject([
        ca: params["ca_instance_id"] || "",
        category: params["category"] || "all",
        action: params["action"] || "",
        actor: params["actor"] || "",
        date_from: params["date_from"] || "",
        date_to: params["date_to"] || ""
      ], fn {_k, v} -> v == "" or v == "all" end)
    )

    path = if query == "", do: "/audit-log", else: "/audit-log?#{query}"
    {:noreply, push_patch(socket, to: path)}
  end

  @export_limit 1000

  @impl true
  def handle_event("export_csv", _params, socket) do
    events = socket.assigns.events
    total = length(events)
    exported = Enum.take(events, @export_limit)
    tz_offset = socket.assigns[:timezone_offset_min] || 0
    tz_name = socket.assigns[:timezone] || "UTC"
    csv = generate_csv(exported, tz_offset, tz_name)
    filename = "audit-log-#{Date.to_iso8601(Date.utc_today())}.csv"

    socket = if total > @export_limit do
      put_flash(socket, :info, "Exported #{@export_limit} of #{total} records. Narrow your filters to export the rest.")
    else
      socket
    end

    {:noreply, push_event(socket, "download", %{content: csv, filename: filename, content_type: "text/csv"})}
  end

  @impl true
  def handle_event("export_json", _params, socket) do
    events = socket.assigns.events
    total = length(events)
    exported = Enum.take(events, @export_limit)
    json = Jason.encode!(exported, pretty: true)
    filename = "audit-log-#{Date.to_iso8601(Date.utc_today())}.json"

    socket = if total > @export_limit do
      put_flash(socket, :info, "Exported #{@export_limit} of #{total} records. Narrow your filters to export the rest.")
    else
      socket
    end

    {:noreply, push_event(socket, "download", %{content: json, filename: filename, content_type: "application/json"})}
  end

  @impl true
  def handle_event("change_page", %{"page" => page}, socket) do
    {:noreply, assign(socket, page: String.to_integer(page))}
  end

  defp generate_csv(events, tz_offset, tz_name) do
    header = "Timestamp (#{tz_name}),Category,Action,Actor,Event ID\r\n"

    rows = Enum.map(events, fn e ->
      timestamp = if e[:timestamp], do: format_with_offset(e.timestamp, tz_offset), else: ""
      "#{csv_escape(timestamp)},#{csv_escape(to_string(e.category))},#{csv_escape(to_string(e.action))},#{csv_escape(to_string(e.actor))},#{csv_escape(to_string(e.event_id))}\r\n"
    end)

    header <> Enum.join(rows)
  end

  defp format_with_offset(dt, offset_min) when is_integer(offset_min) do
    dt
    |> NaiveDateTime.add(offset_min * 60, :second)
    |> Calendar.strftime("%Y-%m-%d %H:%M:%S")
  end
  defp format_with_offset(dt, _), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S")

  defp csv_escape(value) do
    if String.contains?(value, [",", "\"", "\n"]) do
      "\"" <> String.replace(value, "\"", "\"\"") <> "\""
    else
      value
    end
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
    |> Enum.sort_by(& &1[:timestamp] || ~U[0000-01-01 00:00:00Z], {:desc, DateTime})
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
    <div id="audit-log-page" phx-hook="DownloadHook" class="space-y-6">
      <div class="alert border border-info/30 bg-info/5">
        <.icon name="hero-shield-check" class="size-5 text-info shrink-0" />
        <div>
          <p class="text-sm font-medium text-base-content">Audit Trail</p>
          <p class="text-xs text-base-content/60 mt-0.5">
            Tamper-evident audit log supporting WebTrust for CAs, ETSI EN 319 401, ISO 27001, and CA/Browser Forum Baseline Requirements.
            Export records in CSV or JSON format for compliance review and external audit.
          </p>
        </div>
      </div>

      <%!-- Filter form --%>
      <div id="audit-filter" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-4">
          <form phx-submit="apply_filter" class="flex flex-wrap items-end gap-3">
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">CA Instance</label>
              <select name="ca_instance_id" class="select select-bordered select-sm">
                <option value="">All</option>
                <option
                  :for={inst <- @ca_instances}
                  value={inst.id}
                  selected={@selected_ca_instance_id == inst.id}
                >
                  {inst.name}
                </option>
              </select>
            </div>
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">Category</label>
              <select name="category" class="select select-bordered select-sm">
                <option value="all" selected={@category == "all"}>All</option>
                <option value="ca_operations" selected={@category == "ca_operations"}>CA Operations</option>
                <option value="user_management" selected={@category == "user_management"}>User Management</option>
              </select>
            </div>
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">Action</label>
              <select name="action" class="select select-bordered select-sm">
                <option value="">All</option>
                <option value="login" selected={@filter_action == "login"}>Login</option>
                <option value="key_generated" selected={@filter_action == "key_generated"}>Key Generated</option>
                <option value="ceremony_initiated" selected={@filter_action == "ceremony_initiated"}>Ceremony Initiated</option>
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
              <label class="block text-xs font-medium text-base-content/60 mb-1">Actor</label>
              <input type="text" name="actor" value={@filter_actor} class="input input-bordered input-sm w-40" placeholder="Search actor..." />
            </div>
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">From</label>
              <input type="date" name="date_from" value={@filter_date_from} class="input input-bordered input-sm" />
            </div>
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">To</label>
              <input type="date" name="date_to" value={@filter_date_to} class="input input-bordered input-sm" />
            </div>
            <div>
              <button type="submit" class="btn btn-primary btn-sm">
                <.icon name="hero-funnel" class="size-4" />
                Apply Filter
              </button>
            </div>
            <div class="flex gap-1 ml-auto">
              <button type="button" phx-click="export_csv" title="Export CSV" class="btn btn-ghost btn-sm">
                <.icon name="hero-document-arrow-down" class="size-4" /> CSV
              </button>
              <button type="button" phx-click="export_json" title="Export JSON" class="btn btn-ghost btn-sm">
                <.icon name="hero-code-bracket" class="size-4" /> JSON
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
          <div>
            <table class="table table-sm table-fixed w-full">
              <thead>
                <tr class="text-xs uppercase text-base-content/50">
                  <th class="w-[22%]">Timestamp</th>
                  <th class="w-[15%]">Category</th>
                  <th class="w-[15%]">Action</th>
                  <th class="w-[28%]">Actor</th>
                  <th class="w-[20%]">Event ID</th>
                </tr>
              </thead>
              <tbody id="event-list">
                <tr :for={event <- paginated_events} id={"event-#{event.event_id}"} class="hover">
                  <td class="font-mono-data"><.local_time dt={event[:timestamp]} /></td>
                  <td>
                    <span class={["badge badge-sm", if(event.category == "ca_operations", do: "badge-info", else: "badge-secondary")]}>
                      {if event.category == "ca_operations", do: "CA Ops", else: "User Mgmt"}
                    </span>
                  </td>
                  <td>
                    <span class="badge badge-sm badge-ghost">{event.action}</span>
                  </td>
                  <td class="overflow-hidden text-ellipsis whitespace-nowrap">{event.actor}</td>
                  <td class="font-mono-data overflow-hidden text-ellipsis whitespace-nowrap">{event.event_id}</td>
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
