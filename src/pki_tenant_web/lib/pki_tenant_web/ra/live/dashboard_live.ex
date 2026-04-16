defmodule PkiTenantWeb.Ra.DashboardLive do
  use Phoenix.LiveView

  def mount(_params, _session, socket) do
    {:ok, assign(socket, page_title: "RA Dashboard")}
  end

  def render(assigns) do
    ~H"""
    <h1>{@page_title}</h1>
    <p>RA Dashboard placeholder</p>
    """
  end
end
