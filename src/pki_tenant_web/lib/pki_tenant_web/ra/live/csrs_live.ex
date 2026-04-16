defmodule PkiTenantWeb.Ra.CsrsLive do
  use Phoenix.LiveView

  def mount(_params, _session, socket) do
    {:ok, assign(socket, page_title: "CSR Management")}
  end

  def render(assigns) do
    ~H"""
    <h1>{@page_title}</h1>
    <p>CSR Management placeholder</p>
    """
  end
end
