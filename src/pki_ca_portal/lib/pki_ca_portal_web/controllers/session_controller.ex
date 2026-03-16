defmodule PkiCaPortalWeb.SessionController do
  use PkiCaPortalWeb, :controller
  import Plug.Conn

  def new(conn, _params) do
    render(conn, :login, layout: false)
  end

  def create(conn, %{"session" => session_params}) do
    user = %{
      did: session_params["did"],
      role: session_params["role"],
      ca_instance_id: parse_instance_id(session_params["ca_instance_id"])
    }

    conn
    |> configure_session(renew: true)
    |> put_session(:current_user, user)
    |> redirect(to: "/")
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
