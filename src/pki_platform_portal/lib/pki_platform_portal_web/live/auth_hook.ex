defmodule PkiPlatformPortalWeb.Live.AuthHook do
  @moduledoc """
  LiveView on_mount hook that ensures the user is authenticated.
  """
  import Phoenix.LiveView
  import Phoenix.Component

  def on_mount(:default, _params, session, socket) do
    case session do
      %{"current_user" => user} when not is_nil(user) ->
        {:cont, assign(socket, :current_user, user)}

      _ ->
        {:halt, redirect(socket, to: "/login")}
    end
  end
end
