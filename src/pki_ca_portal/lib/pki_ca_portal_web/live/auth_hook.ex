defmodule PkiCaPortalWeb.Live.AuthHook do
  @moduledoc """
  LiveView on_mount hook that loads the current user from the session.

  Redirects to /login if no user is found in the session.
  """

  import Phoenix.LiveView
  import Phoenix.Component

  def on_mount(:default, _params, session, socket) do
    case session["current_user"] do
      nil -> {:halt, redirect(socket, to: "/login")}
      user -> {:cont, assign(socket, :current_user, user)}
    end
  end
end
