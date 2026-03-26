defmodule PkiPlatformPortalWeb.DashboardLive do
  use PkiPlatformPortalWeb, :live_view

  @impl true
  def mount(_params, _session, socket) do
    {:ok, assign(socket, page_title: "Dashboard")}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <.header>
      Dashboard
      <:subtitle>Platform administration overview</:subtitle>
    </.header>

    <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mt-4">
      <div class="card bg-base-100 shadow">
        <div class="card-body">
          <h3 class="card-title text-sm text-base-content/60">Tenants</h3>
          <p class="text-3xl font-bold">--</p>
        </div>
      </div>
    </div>
    """
  end
end
