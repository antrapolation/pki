defmodule PkiTenantWeb.Ca.CertificatesLive do
  use Phoenix.LiveView

  def mount(_params, _session, socket) do
    {:ok, assign(socket, page_title: "Certificates")}
  end

  def render(assigns) do
    ~H"""
    <h1>{@page_title}</h1>
    <p>Certificates placeholder</p>
    """
  end
end
