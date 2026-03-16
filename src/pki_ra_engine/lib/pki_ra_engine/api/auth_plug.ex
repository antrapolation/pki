defmodule PkiRaEngine.Api.AuthPlug do
  @moduledoc """
  Plug that extracts and verifies an API key from the Authorization header.

  Expects: `Authorization: Bearer <base64-encoded-raw-key>`
  """

  import Plug.Conn

  def init(opts), do: opts

  def call(conn, _opts) do
    with ["Bearer " <> key] <- get_req_header(conn, "authorization"),
         {:ok, api_key} <- PkiRaEngine.ApiKeyManagement.verify_key(key) do
      assign(conn, :current_api_key, api_key)
    else
      _ ->
        conn
        |> put_resp_content_type("application/json")
        |> send_resp(401, Jason.encode!(%{error: "unauthorized"}))
        |> halt()
    end
  end
end
