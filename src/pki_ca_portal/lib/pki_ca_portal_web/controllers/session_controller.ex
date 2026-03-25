defmodule PkiCaPortalWeb.SessionController do
  use PkiCaPortalWeb, :controller
  import Plug.Conn

  alias PkiCaPortal.CaEngineClient

  def new(conn, _params) do
    render(conn, :login, layout: false, error: nil)
  end

  def create(conn, %{"session" => %{"username" => username, "password" => password} = params}) do
    ca_instance_id = parse_instance_id(params["ca_instance_id"])

    case CaEngineClient.authenticate(username, password) do
      {:ok, user} ->
        conn
        |> configure_session(renew: true)
        |> put_session(:current_user, %{
          id: user.id,
          username: user.username,
          role: user.role,
          display_name: user.display_name,
          ca_instance_id: ca_instance_id
        })
        |> redirect(to: "/")

      {:error, :invalid_credentials} ->
        render(conn, :login, layout: false, error: "Invalid username or password")
    end
  end

  def delete(conn, _params) do
    conn
    |> clear_session()
    |> redirect(to: "/login")
  end

  defp parse_instance_id(val) when is_binary(val) do
    case Integer.parse(val) do
      {int, _} -> int
      :error -> 1
    end
  end

  defp parse_instance_id(val) when is_integer(val), do: val
  defp parse_instance_id(_), do: 1
end
