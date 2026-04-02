defmodule PkiCaPortalWeb.Live.AuthHook do
  @moduledoc """
  LiveView on_mount hook that loads the current user from the session
  and enforces role-based access control.

  Redirects to /login if no user is found in the session.
  Redirects to / if the user's role cannot access the requested page.
  """

  import Phoenix.LiveView
  import Phoenix.Component

  # Pages each role can access
  @role_pages %{
    "ca_admin" => :all,
    "key_manager" => [
      PkiCaPortalWeb.DashboardLive,
      PkiCaPortalWeb.CaInstancesLive,
      PkiCaPortalWeb.HsmDevicesLive,
      PkiCaPortalWeb.KeystoresLive,
      PkiCaPortalWeb.CeremonyLive,
      PkiCaPortalWeb.IssuerKeysLive,
      PkiCaPortalWeb.ProfileLive
    ],
    "auditor" => [
      PkiCaPortalWeb.DashboardLive,
      PkiCaPortalWeb.CaInstancesLive,
      PkiCaPortalWeb.AuditLogLive,
      PkiCaPortalWeb.ProfileLive
    ]
  }

  def on_mount(:default, _params, session, socket) do
    case session["current_user"] do
      nil ->
        {:halt, redirect(socket, to: "/login")}

      user ->
        tenant_id = session["tenant_id"] || user[:tenant_id]
        role = user[:role] || "auditor"
        view = socket.view

        if allowed?(role, view) do
          {:cont,
           socket
           |> assign(:current_user, user)
           |> assign(:tenant_id, tenant_id)}
        else
          {:halt,
           socket
           |> put_flash(:error, "You don't have access to that page.")
           |> redirect(to: "/")}
        end
    end
  end

  defp allowed?(role, view) do
    case Map.get(@role_pages, role) do
      :all -> true
      nil -> false
      pages -> view in pages
    end
  end
end
