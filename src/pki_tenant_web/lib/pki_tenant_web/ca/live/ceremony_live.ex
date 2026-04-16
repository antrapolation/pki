defmodule PkiTenantWeb.Ca.CeremonyLive do
  use Phoenix.LiveView

  def mount(_params, _session, socket) do
    {:ok, assign(socket, page_title: "Key Ceremonies")}
  end

  def render(assigns) do
    ~H"""
    <h1>{@page_title}</h1>
    <p>Key Ceremonies placeholder</p>
    """
  end
end
