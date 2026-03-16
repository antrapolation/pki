defmodule PkiValidation.Api.Router do
  @moduledoc """
  HTTP router for the PKI Validation service.

  Endpoints:
  - GET  /health — health check
  - POST /ocsp   — OCSP status query (simplified JSON)
  - GET  /crl    — current CRL
  """

  use Plug.Router

  plug :match
  plug Plug.Parsers, parsers: [:json], json_decoder: Jason
  plug :dispatch

  get "/health" do
    send_json(conn, 200, %{status: "ok"})
  end

  post "/ocsp" do
    case conn.body_params do
      %{"serial_number" => serial_number} when is_binary(serial_number) ->
        {:ok, response} = PkiValidation.OcspResponder.check_status(serial_number)
        send_json(conn, 200, response)

      _ ->
        send_json(conn, 400, %{error: "missing or invalid serial_number"})
    end
  end

  get "/crl" do
    {:ok, crl} = PkiValidation.CrlPublisher.get_current_crl()
    send_json(conn, 200, crl)
  end

  match _ do
    send_json(conn, 404, %{error: "not_found"})
  end

  defp send_json(conn, status, body) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(body))
  end
end
