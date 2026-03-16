defmodule PkiCaPortalWeb.DashboardLive do
  use PkiCaPortalWeb, :live_view

  alias PkiCaPortal.CaEngineClient

  @impl true
  def mount(_params, _session, socket) do
    ca_id = socket.assigns.current_user["ca_instance_id"] || 1

    {:ok, status} = CaEngineClient.get_engine_status(ca_id)
    {:ok, keys} = CaEngineClient.list_issuer_keys(ca_id)
    {:ok, ceremonies} = CaEngineClient.list_ceremonies(ca_id)

    {:ok,
     assign(socket,
       page_title: "Dashboard",
       engine_status: status,
       active_keys: keys,
       recent_ceremonies: ceremonies
     )}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div id="dashboard">
      <h1>Dashboard</h1>

      <section id="status-card">
        <h2>Engine Status</h2>
        <p>Status: <span id="engine-status">{@engine_status.status}</span></p>
        <p>Active Keys: <span id="active-key-count">{@engine_status.active_keys}</span></p>
        <p>Uptime: {@engine_status.uptime_seconds}s</p>
      </section>

      <section id="key-summary">
        <h2>Issuer Keys</h2>
        <p>Total keys: <span id="key-count">{length(@active_keys)}</span></p>
      </section>

      <section id="recent-ceremonies">
        <h2>Recent Ceremonies</h2>
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Type</th>
              <th>Status</th>
              <th>Algorithm</th>
            </tr>
          </thead>
          <tbody>
            <tr :for={ceremony <- @recent_ceremonies}>
              <td>{ceremony.id}</td>
              <td>{ceremony.ceremony_type}</td>
              <td>{ceremony.status}</td>
              <td>{ceremony.algorithm}</td>
            </tr>
          </tbody>
        </table>
      </section>

      <section id="quick-actions">
        <h2>Quick Actions</h2>
        <a href="/ceremony" class="btn">Initiate Ceremony</a>
        <a href="/users" class="btn">Manage Users</a>
        <a href="/keystores" class="btn">Manage Keystores</a>
        <a href="/audit-log" class="btn">View Audit Log</a>
      </section>
    </div>
    """
  end
end
