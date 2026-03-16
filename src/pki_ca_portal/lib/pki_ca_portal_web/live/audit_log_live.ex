defmodule PkiCaPortalWeb.AuditLogLive do
  use PkiCaPortalWeb, :live_view

  alias PkiCaPortal.CaEngineClient

  @impl true
  def mount(_params, _session, socket) do
    {:ok, events} = CaEngineClient.query_audit_log([])

    {:ok,
     assign(socket,
       page_title: "Audit Log",
       events: events,
       filter_action: "",
       filter_actor: "",
       filter_date_from: "",
       filter_date_to: ""
     )}
  end

  @impl true
  def handle_event("filter", params, socket) do
    filters =
      []
      |> maybe_add_filter(:action, params["action"])
      |> maybe_add_filter(:actor_did, params["actor_did"])
      |> maybe_add_filter(:date_from, params["date_from"])
      |> maybe_add_filter(:date_to, params["date_to"])

    {:ok, events} = CaEngineClient.query_audit_log(filters)

    {:noreply,
     assign(socket,
       events: events,
       filter_action: params["action"] || "",
       filter_actor: params["actor_did"] || "",
       filter_date_from: params["date_from"] || "",
       filter_date_to: params["date_to"] || ""
     )}
  end

  defp maybe_add_filter(filters, _key, nil), do: filters
  defp maybe_add_filter(filters, _key, ""), do: filters
  defp maybe_add_filter(filters, key, value), do: [{key, value} | filters]

  @impl true
  def render(assigns) do
    ~H"""
    <div id="audit-log-page">
      <h1>Audit Log</h1>

      <section id="audit-filter">
        <h2>Filters</h2>
        <form phx-submit="filter">
          <div>
            <label for="action">Action:</label>
            <select name="action" id="filter-action">
              <option value="">All</option>
              <option value="login" selected={@filter_action == "login"}>Login</option>
              <option value="key_generated" selected={@filter_action == "key_generated"}>
                Key Generated
              </option>
              <option value="ceremony_initiated" selected={@filter_action == "ceremony_initiated"}>
                Ceremony Initiated
              </option>
            </select>
          </div>
          <div>
            <label for="actor_did">Actor DID:</label>
            <input type="text" name="actor_did" id="filter-actor" value={@filter_actor} />
          </div>
          <div>
            <label for="date_from">From:</label>
            <input type="date" name="date_from" id="filter-date-from" value={@filter_date_from} />
          </div>
          <div>
            <label for="date_to">To:</label>
            <input type="date" name="date_to" id="filter-date-to" value={@filter_date_to} />
          </div>
          <button type="submit">Apply Filter</button>
        </form>
      </section>

      <section id="audit-table">
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Action</th>
              <th>Actor</th>
              <th>Event ID</th>
            </tr>
          </thead>
          <tbody id="event-list">
            <tr :for={event <- @events} id={"event-#{event.event_id}"}>
              <td>{Calendar.strftime(event.timestamp, "%Y-%m-%d %H:%M:%S")}</td>
              <td>{event.action}</td>
              <td>{event.actor_did}</td>
              <td>{event.event_id}</td>
            </tr>
          </tbody>
        </table>
      </section>
    </div>
    """
  end
end
