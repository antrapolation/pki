defmodule PkiTenantWeb.Ca.AuditLogLive do
  @moduledoc "CA portal audit log. Delegates to `PkiTenantWeb.AuditLogLiveShared`."
  use PkiTenantWeb, :live_view

  alias PkiTenantWeb.AuditLogLiveShared

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_data)
    {:ok, assign(socket, AuditLogLiveShared.initial_assigns(:ca))}
  end

  @impl true
  def handle_info(:load_data, socket) do
    {:noreply, AuditLogLiveShared.handle_load_data(socket)}
  end

  @impl true
  def handle_event(event, params, socket),
    do: AuditLogLiveShared.handle_event(event, params, socket)

  @impl true
  def render(assigns), do: AuditLogLiveShared.render_page(assigns)
end
