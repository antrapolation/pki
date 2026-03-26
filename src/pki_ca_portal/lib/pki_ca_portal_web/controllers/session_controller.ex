defmodule PkiCaPortalWeb.SessionController do
  use PkiCaPortalWeb, :controller
  import Plug.Conn

  alias PkiCaPortal.CaEngineClient

  def new(conn, _params) do
    render(conn, :login, layout: false, error: nil)
  end

  def create(conn, %{"session" => %{"username" => username, "password" => password} = params}) do
    ca_instance_id = parse_instance_id(params["ca_instance_id"])

    case CaEngineClient.authenticate_with_session(username, password) do
      {:ok, user, session_info} ->
        conn
        |> configure_session(renew: true)
        |> put_session(:current_user, %{
          id: user.id,
          username: user.username,
          role: user.role,
          display_name: user.display_name,
          ca_instance_id: ca_instance_id
        })
        |> put_session(:session_key, session_info[:session_key])
        |> put_session(:session_salt, session_info[:session_salt])
        |> redirect(to: "/")

      {:error, :invalid_credentials} ->
        render(conn, :login, layout: false, error: "Invalid username or password")

      {:error, reason} ->
        require Logger
        Logger.error("Authentication error: #{inspect(reason)}")
        render(conn, :login, layout: false, error: "Service unavailable. Please try again.")
    end
  end

  def delete(conn, _params) do
    conn
    |> clear_session()
    |> redirect(to: "/login")
  end

  defp parse_instance_id(nil), do: "default"
  defp parse_instance_id(val) when is_binary(val), do: val
  defp parse_instance_id(val) when is_integer(val), do: Integer.to_string(val)
  defp parse_instance_id(_), do: "default"
end
