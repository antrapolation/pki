defmodule PkiTenantWeb.AuditLogLiveShared do
  @moduledoc """
  Shared rendering + event handling for the CA and RA audit log
  LiveViews. Backed by `PkiTenant.AuditTrail` against the local
  Mnesia audit table.

  The CA portal shows every category. The RA portal hides
  `ca_operations` rows so RA staff don't see CA-internal events
  they have no use for.
  """

  use Phoenix.Component

  import PkiTenantWeb.CoreComponents, only: [icon: 1, local_time: 1]

  require Logger

  alias Phoenix.LiveView
  alias PkiTenant.AuditTrail

  @export_limit 1_000

  @category_labels %{
    "ca_operations" => "CA Ops",
    "ra_operations" => "RA Ops",
    "user_management" => "User Mgmt",
    "general" => "General"
  }

  @ca_categories ~w(all ca_operations user_management general ra_operations)
  @ra_categories ~w(all ra_operations user_management general)

  @doc "Build the initial assigns for the given portal scope."
  def initial_assigns(scope) when scope in [:ca, :ra] do
    %{
      scope: scope,
      page_title: "Audit Log",
      events: [],
      loading: true,
      filter_action: "",
      filter_actor: "",
      filter_date_from: "",
      filter_date_to: "",
      category: "all",
      page: 1,
      per_page: 10,
      available_categories: categories_for(scope)
    }
  end

  @doc "Load events, applying the current filter assigns."
  def handle_load_data(socket) do
    filters = [
      category: normalize_category(socket.assigns.category, socket.assigns.scope),
      action: socket.assigns.filter_action,
      actor: socket.assigns.filter_actor,
      date_from: socket.assigns.filter_date_from,
      date_to: socket.assigns.filter_date_to
    ]

    events =
      AuditTrail.list_events(filters)
      |> scope_filter(socket.assigns.scope)

    Phoenix.Component.assign(socket, events: events, loading: false, page: 1)
  end

  @doc "Dispatch a UI event to the shared handler."
  def handle_event(event, params, socket) do
    do_event(event, params, socket)
  end

  # --- Event handlers ---

  defp do_event("apply_filter", params, socket) do
    socket =
      Phoenix.Component.assign(socket,
        category: params["category"] || "all",
        filter_action: params["action"] || "",
        filter_actor: params["actor"] || "",
        filter_date_from: params["date_from"] || "",
        filter_date_to: params["date_to"] || ""
      )

    {:noreply, handle_load_data(socket)}
  end

  defp do_event("change_page", %{"page" => page}, socket) do
    case Integer.parse(page) do
      {p, ""} when p > 0 -> {:noreply, Phoenix.Component.assign(socket, page: p)}
      _ -> {:noreply, socket}
    end
  end

  defp do_event("export_csv", _params, socket) do
    {exported, total} = take_export(socket.assigns.events)
    tz_offset = socket.assigns[:timezone_offset_min] || 0
    tz_name = socket.assigns[:timezone] || "UTC"
    csv = generate_csv(exported, tz_offset, tz_name)
    filename = "audit-log-#{Date.to_iso8601(Date.utc_today())}.csv"

    socket = maybe_truncation_flash(socket, total)

    {:noreply,
     LiveView.push_event(socket, "download", %{
       content: csv,
       filename: filename,
       content_type: "text/csv"
     })}
  end

  defp do_event("export_json", _params, socket) do
    {exported, total} = take_export(socket.assigns.events)

    json =
      exported
      |> Enum.map(&serialize_for_json/1)
      |> Jason.encode!(pretty: true)

    filename = "audit-log-#{Date.to_iso8601(Date.utc_today())}.json"

    socket = maybe_truncation_flash(socket, total)

    {:noreply,
     LiveView.push_event(socket, "download", %{
       content: json,
       filename: filename,
       content_type: "application/json"
     })}
  end

  # --- Helpers ---

  defp take_export(events) do
    {Enum.take(events, @export_limit), length(events)}
  end

  defp maybe_truncation_flash(socket, total) do
    if total > @export_limit do
      LiveView.put_flash(
        socket,
        :info,
        "Exported #{@export_limit} of #{total} records. Narrow your filters to export the rest."
      )
    else
      socket
    end
  end

  defp categories_for(:ca), do: @ca_categories
  defp categories_for(:ra), do: @ra_categories

  # When an RA operator selects "all", translate that to a tenant-wide
  # query and then drop ca_operations on display.
  defp normalize_category("all", _scope), do: "all"

  defp normalize_category(cat, :ra) when cat == "ca_operations" do
    # Operator shouldn't be able to pick this in the RA select, but
    # if URL state or XSS ever tries, coerce to RA-safe default.
    "ra_operations"
  end

  defp normalize_category(cat, _scope), do: cat

  defp scope_filter(events, :ca), do: events
  defp scope_filter(events, :ra), do: Enum.reject(events, &(&1.category == "ca_operations"))

  defp serialize_for_json(entry) do
    %{
      id: entry.id,
      timestamp: entry.timestamp,
      action: entry.action,
      category: entry.category,
      actor: entry.actor,
      actor_role: entry.actor_role,
      metadata: stringify_keys(entry.metadata)
    }
  end

  defp stringify_keys(map) when is_map(map) do
    Map.new(map, fn {k, v} -> {to_string(k), v} end)
  end

  defp stringify_keys(other), do: other

  defp generate_csv(events, tz_offset, tz_name) do
    header = "Timestamp (#{tz_name}),Category,Action,Actor,Event ID\r\n"

    rows =
      Enum.map(events, fn e ->
        timestamp = format_with_offset(e.timestamp, tz_offset)

        [timestamp, to_string(e.category), to_string(e.action), to_string(e.actor), to_string(e.id)]
        |> Enum.map_join(",", &csv_escape/1)
        |> Kernel.<>("\r\n")
      end)

    header <> Enum.join(rows)
  end

  defp format_with_offset(dt, offset_min) when is_integer(offset_min) and offset_min != 0 do
    dt
    |> DateTime.add(offset_min * 60, :second)
    |> Calendar.strftime("%Y-%m-%d %H:%M:%S")
  end

  defp format_with_offset(dt, _), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S")

  defp csv_escape(value) do
    str = to_string(value)

    if String.contains?(str, [",", "\"", "\n"]) do
      "\"" <> String.replace(str, "\"", "\"\"") <> "\""
    else
      str
    end
  end

  defp category_label(cat), do: Map.get(@category_labels, cat, cat)

  defp category_badge_class("ca_operations"), do: "badge-info"
  defp category_badge_class("ra_operations"), do: "badge-primary"
  defp category_badge_class("user_management"), do: "badge-secondary"
  defp category_badge_class("general"), do: "badge-ghost"
  defp category_badge_class(_), do: "badge-ghost"

  # --- Render ---

  def render_page(assigns) do
    ~H"""
    <div id="audit-log-page" phx-hook="DownloadHook" class="space-y-6">
      <div class="alert border border-info/30 bg-info/5">
        <.icon name="hero-shield-check" class="size-5 text-info shrink-0" />
        <div>
          <p class="text-sm font-medium text-base-content">Audit Trail</p>
          <p class="text-xs text-base-content/60 mt-0.5">
            Tenant-local audit events, mirrored to the platform for compliance retention
            (WebTrust for CAs, ETSI EN 319 401, ISO 27001, CA/Browser Forum Baseline Requirements).
            Export records in CSV or JSON format for external audit.
          </p>
        </div>
      </div>

      <%!-- Filter form --%>
      <div id="audit-filter" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-4">
          <form phx-submit="apply_filter" class="flex flex-wrap items-end gap-3">
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">Category</label>
              <select name="category" class="select select-bordered select-sm">
                <option :for={cat <- @available_categories} value={cat} selected={@category == cat}>
                  {category_label(cat)}
                </option>
              </select>
            </div>
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">Action</label>
              <input
                type="text"
                name="action"
                value={@filter_action}
                class="input input-bordered input-sm w-48"
                placeholder="e.g. user_created"
              />
            </div>
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">Actor</label>
              <input
                type="text"
                name="actor"
                value={@filter_actor}
                class="input input-bordered input-sm w-40"
                placeholder="username substring"
              />
            </div>
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">From</label>
              <input
                type="date"
                name="date_from"
                value={@filter_date_from}
                class="input input-bordered input-sm"
              />
            </div>
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">To</label>
              <input
                type="date"
                name="date_to"
                value={@filter_date_to}
                class="input input-bordered input-sm"
              />
            </div>
            <div>
              <button type="submit" class="btn btn-primary btn-sm">
                <.icon name="hero-funnel" class="size-4" /> Apply
              </button>
            </div>
            <div class="flex gap-1 ml-auto">
              <button
                type="button"
                phx-click="export_csv"
                title="Export CSV"
                class="btn btn-ghost btn-sm"
              >
                <.icon name="hero-document-arrow-down" class="size-4" /> CSV
              </button>
              <button
                type="button"
                phx-click="export_json"
                title="Export JSON"
                class="btn btn-ghost btn-sm"
              >
                <.icon name="hero-code-bracket" class="size-4" /> JSON
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
          <div :if={@loading} class="p-8 text-center text-base-content/40 text-sm">Loading…</div>

          <div :if={not @loading and total == 0} class="p-8 text-center text-base-content/50 text-sm">
            No audit events match the current filter.
          </div>

          <div :if={not @loading and total > 0}>
            <table class="table table-sm table-fixed w-full">
              <thead>
                <tr class="text-xs uppercase text-base-content/50">
                  <th class="w-[22%]">Timestamp</th>
                  <th class="w-[14%]">Category</th>
                  <th class="w-[22%]">Action</th>
                  <th class="w-[22%]">Actor</th>
                  <th class="w-[20%]">Event ID</th>
                </tr>
              </thead>
              <tbody id="event-list">
                <tr :for={event <- paginated} id={"event-#{event.id}"} class="hover">
                  <td class="font-mono-data">
                    <.local_time dt={event.timestamp} />
                  </td>
                  <td>
                    <span class={"badge badge-sm #{category_badge_class(event.category)}"}>
                      {category_label(event.category)}
                    </span>
                  </td>
                  <td>
                    <span class="badge badge-sm badge-ghost">{event.action}</span>
                  </td>
                  <td class="overflow-hidden text-ellipsis whitespace-nowrap">{event.actor}</td>
                  <td class="font-mono-data overflow-hidden text-ellipsis whitespace-nowrap">
                    {String.slice(to_string(event.id), 0..13)}
                  </td>
                </tr>
              </tbody>
            </table>

            <div class="flex items-center justify-between px-5 py-3 border-t border-base-300 text-sm">
              <span class="text-base-content/60">Showing {start_idx}–{end_idx} of {total}</span>
              <div class="join">
                <button
                  class="join-item btn btn-sm"
                  phx-click="change_page"
                  phx-value-page={@page - 1}
                  disabled={@page == 1}
                >
                  «
                </button>
                <button class="join-item btn btn-sm btn-active">{@page}</button>
                <button
                  class="join-item btn btn-sm"
                  phx-click="change_page"
                  phx-value-page={@page + 1}
                  disabled={@page >= total_pages}
                >
                  »
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
  end
end
