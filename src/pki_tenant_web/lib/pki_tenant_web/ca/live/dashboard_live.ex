defmodule PkiTenantWeb.Ca.DashboardLive do
  use Phoenix.LiveView

  def mount(_params, _session, socket) do
    {:ok, assign(socket, page_title: "CA Dashboard")}
  end

  def render(assigns) do
    ~H"""
    <h1>{@page_title}</h1>
    <p>CA Dashboard placeholder</p>
    """
  end
end
