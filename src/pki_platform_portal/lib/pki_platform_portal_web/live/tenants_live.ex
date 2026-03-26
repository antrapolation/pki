defmodule PkiPlatformPortalWeb.TenantsLive do
  use PkiPlatformPortalWeb, :live_view

  @impl true
  def mount(_params, _session, socket) do
    {:ok, assign(socket, page_title: "Tenants")}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <.header>
      Tenants
      <:subtitle>Manage platform tenants</:subtitle>
    </.header>

    <p class="text-base-content/60 mt-4">Tenant management will be implemented in a subsequent task.</p>
    """
  end
end
