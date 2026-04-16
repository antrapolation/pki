defmodule PkiTenantWeb.Ca.IssuerKeysLive do
  use Phoenix.LiveView

  def mount(_params, _session, socket) do
    {:ok, assign(socket, page_title: "Issuer Keys")}
  end

  def render(assigns) do
    ~H"""
    <h1>{@page_title}</h1>
    <p>Issuer Keys placeholder</p>
    """
  end
end
