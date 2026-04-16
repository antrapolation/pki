defmodule PkiTenantWeb.Ra.ApiKeysLive do
  use Phoenix.LiveView

  def mount(_params, _session, socket) do
    {:ok, assign(socket, page_title: "API Keys")}
  end

  def render(assigns) do
    ~H"""
    <h1>{@page_title}</h1>
    <p>API Keys placeholder</p>
    """
  end
end
