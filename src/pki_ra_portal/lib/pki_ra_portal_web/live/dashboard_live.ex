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
       cert_profile_count: length(profiles)
     )}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div id="dashboard">
      <h1>Dashboard</h1>

      <section id="status-card">
        <h2>RA Overview</h2>
        <p>Pending CSRs: <span id="pending-csr-count">{@pending_csr_count}</span></p>
        <p>Certificate Profiles: <span id="cert-profile-count">{@cert_profile_count}</span></p>
      </section>

      <section id="recent-csrs">
        <h2>Recent CSRs</h2>
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Subject</th>
              <th>Profile</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            <tr :for={csr <- @recent_csrs}>
              <td>{csr.id}</td>
              <td>{csr.subject}</td>
              <td>{csr.profile_name}</td>
              <td>{csr.status}</td>
            </tr>
          </tbody>
        </table>
      </section>

      <section id="quick-actions">
        <h2>Quick Actions</h2>
        <a href="/csrs" class="btn">Manage CSRs</a>
        <a href="/users" class="btn">Manage Users</a>
        <a href="/cert-profiles" class="btn">Certificate Profiles</a>
        <a href="/service-configs" class="btn">Service Configs</a>
        <a href="/api-keys" class="btn">API Keys</a>
      </section>
    </div>
    """
  end
end
