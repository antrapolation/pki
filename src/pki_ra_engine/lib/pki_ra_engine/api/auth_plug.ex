defmodule PkiRaEngine.Api.AuthPlug do
  @moduledoc """
  Plug that authenticates requests via the Authorization header.

  Accepts two forms of Bearer token:
  1. **Internal API secret** — used by the RA Portal for portal-to-engine calls.
     Configured via `config :pki_ra_engine, :internal_api_secret`.
  2. **API key** — used by external clients (base64-encoded raw key).
     Verified via `ApiKeyManagement.verify_key/1`.

  The internal secret is checked first for efficiency. If neither matches,
  the request is rejected with 401.
  """

  import Plug.Conn

  def init(opts), do: opts

  def call(conn, _opts) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] ->
        cond do
          valid_internal_secret?(token) ->
            assign(conn, :auth_type, :internal)

          true ->
            case PkiRaEngine.ApiKeyManagement.verify_key(token) do
              {:ok, api_key} ->
                conn
                |> assign(:auth_type, :api_key)
                |> assign(:current_api_key, api_key)

              _ ->
                unauthorized(conn)
            end
        end

      _ ->
        unauthorized(conn)
    end
  end

  defp valid_internal_secret?(token) do
    expected = Application.get_env(:pki_ra_engine, :internal_api_secret)
    is_binary(expected) and expected != "" and Plug.Crypto.secure_compare(token, expected)
  end

  defp unauthorized(conn) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(401, Jason.encode!(%{error: "unauthorized"}))
    |> halt()
  end
end
