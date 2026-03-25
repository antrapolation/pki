defmodule PkiCaEngine.Api.AuthPlug do
  @moduledoc """
  Plug that verifies an internal API secret from the Authorization header.

  Expects: `Authorization: Bearer <INTERNAL_API_SECRET>`

  The secret is configured via `config :pki_ca_engine, :internal_api_secret`.
  """

  import Plug.Conn

  def init(opts), do: opts

  def call(conn, _opts) do
    expected_secret = Application.get_env(:pki_ca_engine, :internal_api_secret)

    with ["Bearer " <> token] <- get_req_header(conn, "authorization"),
         true <- is_binary(expected_secret) and expected_secret != "",
         true <- Plug.Crypto.secure_compare(token, expected_secret) do
      conn
    else
      _ ->
        conn
        |> put_resp_content_type("application/json")
        |> send_resp(401, Jason.encode!(%{error: "unauthorized"}))
        |> halt()
    end
  end
end
