defmodule PkiTenantWeb.Ca.UsersLive do
  @moduledoc "CA portal user management. Delegates to `PkiTenantWeb.UsersLiveShared`."
  use PkiTenantWeb, :live_view

  alias PkiTenantWeb.UsersLiveShared

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_data)
    {:ok, assign(socket, UsersLiveShared.initial_assigns(:ca, "ca_admin"))}
  end

  @impl true
  def handle_info(:load_data, socket) do
    {:noreply, UsersLiveShared.handle_load_data(socket)}
  end

  @impl true
  def handle_event(event, params, socket),
    do: UsersLiveShared.handle_event(event, params, socket)

  @impl true
  def render(assigns), do: UsersLiveShared.render_page(assigns)
end
