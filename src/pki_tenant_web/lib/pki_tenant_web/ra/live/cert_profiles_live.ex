defmodule PkiTenantWeb.Ra.CertProfilesLive do
  use Phoenix.LiveView

  def mount(_params, _session, socket) do
    {:ok, assign(socket, page_title: "Certificate Profiles")}
  end

  def render(assigns) do
    ~H"""
    <h1>{@page_title}</h1>
    <p>Certificate Profiles placeholder</p>
    """
  end
end
