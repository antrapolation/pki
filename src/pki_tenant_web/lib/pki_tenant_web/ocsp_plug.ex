defmodule PkiTenantWeb.OcspPlug do
  @moduledoc """
  HTTP plug that accepts DER-encoded OCSP requests (RFC 6960) and returns
  DER-encoded OCSP responses.

  POST /  — body must be a DER-encoded OCSPRequest
  GET  /  — not supported (returns 405)

  Decodes the request via `PkiValidation.Ocsp.RequestDecoder`, then builds a
  signed DER response via `PkiValidation.Ocsp.DerResponder`.

  The `issuer_key_id` is expected to be carried as a query param or connection
  assign set by the tenant endpoint.  When absent the response is unsigned
  (DerResponder returns an :unauthorized payload which is still a valid
  DER OCSP response).
  """
  import Plug.Conn

  alias PkiValidation.Ocsp.{RequestDecoder, DerResponder}

  def init(opts), do: opts

  def call(%{method: "POST"} = conn, _opts) do
    {:ok, body, conn} = Plug.Conn.read_body(conn)

    case RequestDecoder.decode(body) do
      {:ok, request} ->
        issuer_key_id = conn.assigns[:issuer_key_id] ||
          conn.params["issuer_key_id"]

        opts = if issuer_key_id, do: [issuer_key_id: issuer_key_id], else: []

        case DerResponder.respond(request, opts) do
          {:ok, response_der} ->
            conn
            |> put_resp_content_type("application/ocsp-response")
            |> send_resp(200, response_der)

          {:error, _reason} ->
            conn
            |> put_resp_content_type("application/ocsp-response")
            |> send_resp(500, "")
        end

      {:error, :malformed} ->
        conn
        |> put_resp_content_type("application/ocsp-response")
        |> send_resp(400, "")
    end
  end

  def call(conn, _opts) do
    conn |> send_resp(405, "Method not allowed") |> halt()
  end
end
