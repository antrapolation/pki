defmodule PkiValidation.Api.Router do
  @moduledoc """
  HTTP router for the PKI Validation service.

  Endpoints:
  - GET  /health           — health check
  - POST /ocsp             — OCSP status query (simplified JSON, legacy)
  - POST /ocsp/der         — RFC 6960 OCSP (application/ocsp-request)
  - GET  /ocsp/der/:base64 — RFC 5019 lightweight OCSP (GET form)
  - GET  /crl              — current CRL (JSON, legacy)
  - GET  /crl/der          — RFC 5280 DER CRL (default issuer)
  - GET  /crl/der/:issuer_key_id — RFC 5280 DER CRL for a specific issuer
  - POST /notify/issuance  — CA notifies of new certificate (internal, authenticated)
  - POST /notify/revocation — CA notifies of certificate revocation (internal, authenticated)
  - POST /notify/signing-key-rotation — trigger SigningKeyStore.reload/0 (internal, authenticated)
  """

  use Plug.Router

  require Logger

  alias PkiValidation.Repo
  alias PkiValidation.Schema.{CertificateStatus, SigningKeyConfig}
  alias PkiValidation.OcspCache

  import Ecto.Query

  plug :match

  plug Plug.Parsers,
    parsers: [:json],
    pass: ["application/ocsp-request"],
    json_decoder: Jason

  plug :dispatch

  get "/health" do
    case PkiValidation.SigningKeyStore.status() do
      %{healthy: true, loaded: loaded} ->
        send_json(conn, 200, %{status: "ok", signing_keys_loaded: loaded})

      %{loaded: loaded, failed: failed, last_error: last_error} ->
        send_json(conn, 503, %{
          status: "degraded",
          signing_keys_loaded: loaded,
          signing_keys_failed: failed,
          last_error: if(last_error, do: Atom.to_string(last_error), else: nil)
        })
    end
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

  post "/notify/issuance" do
    with :ok <- verify_internal_auth(conn),
         {:ok, attrs} <- validate_issuance_params(conn.body_params) do
      changeset = CertificateStatus.changeset(%CertificateStatus{}, attrs)

      case Repo.insert(changeset) do
        {:ok, record} ->
          Logger.info("Certificate issuance recorded: serial=#{record.serial_number}")
          send_json(conn, 201, %{status: "ok", serial_number: record.serial_number})

        {:error, changeset} ->
          errors = format_changeset_errors(changeset)
          Logger.warning("Certificate issuance notification rejected: #{inspect(errors)}")
          send_json(conn, 422, %{error: "validation_failed", details: errors})
      end
    else
      {:error, :unauthorized} ->
        send_json(conn, 401, %{error: "unauthorized"})

      {:error, :invalid_params, message} ->
        send_json(conn, 400, %{error: message})
    end
  end

  post "/notify/revocation" do
    with :ok <- verify_internal_auth(conn),
         {:ok, serial_number, reason} <- validate_revocation_params(conn.body_params) do
      query = from(cs in CertificateStatus, where: cs.serial_number == ^serial_number)

      case Repo.one(query) do
        nil ->
          send_json(conn, 404, %{error: "certificate_not_found"})

        %CertificateStatus{status: "revoked"} ->
          send_json(conn, 409, %{error: "already_revoked"})

        %CertificateStatus{} = cert ->
          now = DateTime.utc_now() |> DateTime.truncate(:second)

          changeset =
            CertificateStatus.changeset(cert, %{
              status: "revoked",
              revoked_at: now,
              revocation_reason: reason
            })

          case Repo.update(changeset) do
            {:ok, _updated} ->
              OcspCache.invalidate(serial_number)

              Logger.info(
                "Certificate revocation recorded: serial=#{serial_number} reason=#{reason}"
              )

              send_json(conn, 200, %{status: "ok", serial_number: serial_number})

            {:error, changeset} ->
              errors = format_changeset_errors(changeset)
              Logger.warning("Certificate revocation notification rejected: #{inspect(errors)}")
              send_json(conn, 422, %{error: "validation_failed", details: errors})
          end
      end
    else
      {:error, :unauthorized} ->
        send_json(conn, 401, %{error: "unauthorized"})

      {:error, :invalid_params, message} ->
        send_json(conn, 400, %{error: message})
    end
  end

  post "/ocsp/der" do
    case Plug.Conn.read_body(conn, length: 1_000_000) do
      {:ok, body, conn} ->
        handle_der_ocsp_body(conn, body)

      {:more, _partial, conn} ->
        # Body exceeded our 1 MB cap — treat as malformed rather than
        # attempt to process an unbounded OCSP request.
        send_malformed_ocsp(conn)

      {:error, _reason} ->
        send_malformed_ocsp(conn)
    end
  end

  get "/ocsp/der/:b64" do
    case decode_ocsp_get_param(b64) do
      {:ok, der_request} ->
        case PkiValidation.Ocsp.RequestDecoder.decode(der_request) do
          {:ok, request} ->
            respond_der_ocsp(conn, request)

          {:error, :malformed} ->
            send_malformed_ocsp(conn)
        end

      :error ->
        send_malformed_ocsp(conn)
    end
  end

  get "/crl/der" do
    case first_active_issuer_key_id() do
      nil -> send_resp(conn, 503, "")
      issuer_key_id -> serve_crl(conn, issuer_key_id)
    end
  end

  get "/crl/der/:issuer_key_id" do
    serve_crl(conn, issuer_key_id)
  end

  post "/notify/signing-key-rotation" do
    case verify_internal_auth(conn) do
      :ok ->
        PkiValidation.SigningKeyStore.reload()
        Logger.info("SigningKeyStore reloaded via /notify/signing-key-rotation")
        send_json(conn, 200, %{status: "ok"})

      {:error, :unauthorized} ->
        send_json(conn, 401, %{error: "unauthorized"})
    end
  end

  match _ do
    send_json(conn, 404, %{error: "not_found"})
  end

  # -- Private helpers --

  defp send_json(conn, status, body) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(body))
  end

  defp verify_internal_auth(conn) do
    expected_secret = Application.get_env(:pki_validation, :internal_api_secret)

    case Plug.Conn.get_req_header(conn, "authorization") do
      ["Bearer " <> token] when is_binary(expected_secret) and expected_secret != "" ->
        if Plug.Crypto.secure_compare(token, expected_secret) do
          :ok
        else
          {:error, :unauthorized}
        end

      _ ->
        {:error, :unauthorized}
    end
  end

  defp validate_issuance_params(params) do
    required = ~w(serial_number issuer_key_id subject_dn not_before not_after)

    case check_required(params, required) do
      :ok ->
        {:ok,
         %{
           serial_number: params["serial_number"],
           issuer_key_id: params["issuer_key_id"],
           subject_dn: params["subject_dn"],
           status: "active",
           not_before: parse_datetime(params["not_before"]),
           not_after: parse_datetime(params["not_after"])
         }}

      {:error, missing} ->
        {:error, :invalid_params, "missing required fields: #{Enum.join(missing, ", ")}"}
    end
  end

  defp validate_revocation_params(params) do
    case {params["serial_number"], params["reason"]} do
      {serial, reason}
      when is_binary(serial) and serial != "" and is_binary(reason) and reason != "" ->
        {:ok, serial, reason}

      _ ->
        {:error, :invalid_params, "missing required fields: serial_number, reason"}
    end
  end

  defp check_required(params, fields) do
    missing =
      Enum.filter(fields, fn field ->
        value = params[field]
        is_nil(value) or (is_binary(value) and value == "")
      end)

    if missing == [], do: :ok, else: {:error, missing}
  end

  defp parse_datetime(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, dt, _offset} -> dt
      _ -> value
    end
  end

  defp parse_datetime(value), do: value

  defp handle_der_ocsp_body(conn, body) do
    case PkiValidation.Ocsp.RequestDecoder.decode(body) do
      {:ok, request} ->
        respond_der_ocsp(conn, request)

      {:error, :malformed} ->
        send_malformed_ocsp(conn)
    end
  end

  # Guard the DerResponder.respond/2 result. The orchestrator's internal
  # rescue branch can still return {:error, _} if the ASN.1 encoder itself
  # fails while producing an :internalError response. In that rare case we
  # can't produce a signed body at all, so fall back to a bare HTTP 500.
  defp respond_der_ocsp(conn, request) do
    case PkiValidation.Ocsp.DerResponder.respond(request, []) do
      {:ok, der} ->
        send_der_ocsp(conn, der)

      {:error, _reason} ->
        send_resp(conn, 500, "")
    end
  end

  defp send_der_ocsp(conn, der) do
    etag = :crypto.hash(:sha256, der) |> Base.encode16(case: :lower)

    conn
    |> put_resp_header("content-type", "application/ocsp-response")
    |> put_resp_header("cache-control", "public, max-age=300, no-transform")
    |> put_resp_header("etag", "\"#{etag}\"")
    |> send_resp(200, der)
  end

  defp send_malformed_ocsp(conn) do
    {:ok, der} =
      PkiValidation.Ocsp.ResponseBuilder.build(:malformedRequest, [], dummy_signing_key())

    send_der_ocsp(conn, der)
  end

  # ResponseBuilder.build/4 requires a signing_key argument even for error
  # statuses, but the error path never signs anything — it just produces an
  # OCSPResponse with `:asn1_NOVALUE` body.
  defp dummy_signing_key do
    %{algorithm: "ecc_p256", private_key: <<>>, certificate_der: <<>>}
  end

  # Try url-safe base64 first (RFC 5019 permits it). Some clients use
  # standard base64 (possibly URL-encoded by the HTTP layer); fall back to
  # that so both forms round-trip.
  defp decode_ocsp_get_param(b64) when is_binary(b64) do
    case Base.url_decode64(b64, padding: false) do
      {:ok, bin} ->
        {:ok, bin}

      :error ->
        case Base.url_decode64(b64, padding: true) do
          {:ok, bin} ->
            {:ok, bin}

          :error ->
            case Base.decode64(b64, padding: false) do
              {:ok, bin} ->
                {:ok, bin}

              :error ->
                Base.decode64(b64, padding: true)
            end
        end
    end
  end

  defp serve_crl(conn, issuer_key_id) do
    case PkiValidation.SigningKeyStore.get(issuer_key_id) do
      {:ok, signing_key} ->
        case PkiValidation.Crl.DerGenerator.generate(issuer_key_id, signing_key) do
          {:ok, der, crl_number} ->
            conn
            |> put_resp_header("content-type", "application/pkix-crl")
            |> put_resp_header("cache-control", "public, max-age=3600, no-transform")
            |> put_resp_header("etag", "\"#{crl_number}-#{short_id(issuer_key_id)}\"")
            |> send_resp(200, der)

          {:error, _reason} ->
            send_resp(conn, 503, "")
        end

      :not_found ->
        send_resp(conn, 404, "")
    end
  end

  defp first_active_issuer_key_id do
    Repo.one(
      from c in SigningKeyConfig,
        where: c.status == "active",
        order_by: [asc: c.inserted_at],
        limit: 1,
        select: c.issuer_key_id
    )
  end

  defp short_id(id) when is_binary(id),
    do: binary_part(id, 0, min(8, byte_size(id)))

  defp format_changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
