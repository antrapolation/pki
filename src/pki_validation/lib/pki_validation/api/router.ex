defmodule PkiValidation.Api.Router do
  @moduledoc """
  HTTP router for the PKI Validation service.

  Endpoints:
  - GET  /health           — health check
  - POST /ocsp             — OCSP status query (simplified JSON)
  - POST /ocsp/der         — RFC 6960 OCSP (application/ocsp-request)
  - GET  /ocsp/der/:base64 — RFC 5019 lightweight OCSP (GET form)
  - GET  /crl              — current CRL (JSON)
  - GET  /crl/der/:issuer_key_id — RFC 5280 DER CRL for a specific issuer
  - POST /notify/issuance  — CA notifies of new certificate (internal, authenticated)
  - POST /notify/revocation — CA notifies of certificate revocation (internal, authenticated)
  """

  use Plug.Router

  require Logger

  alias PkiMnesia.{Repo, Structs.CertificateStatus, Structs.IssuerKey}

  plug :match

  plug Plug.Parsers,
    parsers: [:json],
    pass: ["application/ocsp-request"],
    json_decoder: Jason

  plug :dispatch

  get "/health" do
    crl_status =
      case PkiValidation.CrlPublisher.get_current_crls() do
        {:ok, crls} ->
          gen_error = case PkiValidation.CrlPublisher.status() do
            %{generation_error: err} -> err
            _ -> false
          end
          total = crls |> Enum.map(fn {_, crl} -> crl.total_revoked end) |> Enum.sum()
          %{issuer_count: map_size(crls), total_revoked: total, generation_error: gen_error}
        _ ->
          %{error: "unavailable"}
      end

    send_json(conn, 200, %{status: "ok", crl: crl_status})
  end

  post "/ocsp" do
    case conn.body_params do
      %{"serial_number" => serial_number} when is_binary(serial_number) ->
        case PkiValidation.OcspResponder.check_status(serial_number) do
          {:ok, response} ->
            send_json(conn, 200, response)

          {:error, reason} ->
            Logger.error("OCSP check failed for serial #{serial_number}: #{inspect(reason)}")
            send_json(conn, 500, %{error: "OCSP check failed"})
        end

      _ ->
        send_json(conn, 400, %{error: "missing or invalid serial_number"})
    end
  end

  get "/crl" do
    case PkiValidation.CrlPublisher.get_current_crls() do
      {:ok, crls} ->
        summary =
          Enum.map(crls, fn {issuer_key_id, crl} ->
            %{
              issuer_key_id: issuer_key_id,
              total_revoked: crl.total_revoked,
              this_update: crl.this_update,
              next_update: crl.next_update
            }
          end)
        send_json(conn, 200, %{crls: summary})

      {:error, reason} ->
        Logger.error("CRL fetch failed: #{inspect(reason)}")
        send_json(conn, 500, %{error: "CRL generation failed"})
    end
  end

  post "/notify/issuance" do
    with :ok <- verify_internal_auth(conn),
         {:ok, attrs} <- validate_issuance_params(conn.body_params) do
      cs = CertificateStatus.new(attrs)

      case Repo.insert(cs) do
        {:ok, record} ->
          Logger.info("Certificate issuance recorded: serial=#{record.serial_number}")
          send_json(conn, 201, %{status: "ok", serial_number: record.serial_number})

        {:error, reason} ->
          Logger.warning("Certificate issuance notification failed: #{inspect(reason)}")
          send_json(conn, 422, %{error: "insert_failed", details: inspect(reason)})
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
      # Lookup then update in Mnesia transaction
      result =
        Repo.transaction(fn ->
          case :mnesia.index_read(:certificate_status, serial_number, :serial_number) do
            [] ->
              :not_found

            [record | _] ->
              cs = PkiMnesia.Repo.record_to_struct(CertificateStatus, record)

              case cs.status do
                "revoked" ->
                  :already_revoked

                _ ->
                  now = DateTime.utc_now() |> DateTime.truncate(:second)
                  updated = %{cs | status: "revoked", revoked_at: now, revocation_reason: reason, updated_at: now}
                  :mnesia.write(PkiMnesia.Repo.struct_to_record(:certificate_status, updated))
                  {:revoked, updated}
              end
          end
        end)

      case result do
        {:ok, :not_found} ->
          send_json(conn, 404, %{error: "certificate_not_found"})

        {:ok, :already_revoked} ->
          send_json(conn, 409, %{error: "already_revoked"})

        {:ok, {:revoked, updated}} ->
          # Force CRL regeneration on revocation
          PkiValidation.CrlPublisher.regenerate()
          Logger.info("Certificate revocation recorded: serial=#{serial_number} reason=#{reason}")
          send_json(conn, 200, %{status: "ok", serial_number: updated.serial_number})

        {:error, reason} ->
          Logger.error("Certificate revocation failed: #{inspect(reason)}")
          send_json(conn, 500, %{error: "internal_error"})
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

  get "/crl/der/:issuer_key_id" do
    case PkiValidation.Crl.DerGenerator.generate(issuer_key_id) do
      {:ok, der, crl_number} ->
        conn
        |> put_resp_header("content-type", "application/pkix-crl")
        |> put_resp_header("cache-control", "public, max-age=3600, no-transform")
        |> put_resp_header("etag", "\"#{crl_number}-#{short_id(issuer_key_id)}\"")
        |> send_resp(200, der)

      {:error, :key_not_active} ->
        send_resp(conn, 503, "")

      {:error, _reason} ->
        send_resp(conn, 500, "")
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
    required = ~w(serial_number issuer_key_id not_after)

    case check_required(params, required) do
      :ok ->
        not_after = parse_datetime(params["not_after"])
        not_before = parse_datetime(params["not_before"])

        with {:not_after, %DateTime{}} <- {:not_after, not_after} do
          {:ok, %{
            serial_number: params["serial_number"],
            issuer_key_id: params["issuer_key_id"],
            status: "active",
            not_before: if(match?(%DateTime{}, not_before), do: not_before, else: nil),
            not_after: not_after
          }}
        else
          {:not_after, _} ->
            {:error, :invalid_params, "not_after is not a valid ISO 8601 datetime"}
        end

      {:error, missing} ->
        {:error, :invalid_params, "missing required fields: #{Enum.join(missing, ", ")}"}
    end
  end

  @valid_revocation_reasons ~w(
    unspecified key_compromise ca_compromise affiliation_changed
    superseded cessation_of_operation certificate_hold
    remove_from_crl privilege_withdrawn aa_compromise certificate_expired
  )

  defp validate_revocation_params(params) do
    case {params["serial_number"], params["reason"]} do
      {serial, reason}
      when is_binary(serial) and serial != "" and is_binary(reason) and reason != "" ->
        if reason in @valid_revocation_reasons do
          {:ok, serial, reason}
        else
          {:error, :invalid_params, "invalid revocation reason: #{reason}"}
        end

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
      _ -> nil
    end
  end

  defp parse_datetime(%DateTime{} = value), do: value
  defp parse_datetime(_), do: nil

  defp handle_der_ocsp_body(conn, body) do
    case PkiValidation.Ocsp.RequestDecoder.decode(body) do
      {:ok, request} ->
        respond_der_ocsp(conn, request)

      {:error, :malformed} ->
        send_malformed_ocsp(conn)
    end
  end

  defp respond_der_ocsp(conn, request) do
    issuer_key_id = resolve_issuer_key_id(request)

    case PkiValidation.Ocsp.DerResponder.respond(request, issuer_key_id: issuer_key_id) do
      {:ok, der} ->
        send_der_ocsp(conn, der)

      {:error, _reason} ->
        send_resp(conn, 500, "")
    end
  end

  # Try to find the issuer_key_id from the request's issuer_name_hash or
  # issuer_key_hash by scanning IssuerKey records. Falls back to nil (which
  # causes DerResponder to return :unauthorized).
  defp resolve_issuer_key_id(%{cert_ids: [%{issuer_key_hash: hash} | _]}) when is_binary(hash) do
    case Repo.where(IssuerKey, fn k -> k.status == "active" end) do
      {:ok, keys} ->
        Enum.find_value(keys, nil, fn key ->
          if key.certificate_der do
            key_hash = PkiValidation.CertId.issuer_key_hash(key.certificate_der)
            if key_hash == hash, do: key.id
          end
        end)

      _ ->
        nil
    end
  end

  defp resolve_issuer_key_id(_), do: nil

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

  defp dummy_signing_key do
    %{algorithm: "ecc_p256", private_key: <<>>, certificate_der: <<>>}
  end

  defp decode_ocsp_get_param(b64) when is_binary(b64) do
    with :error <- Base.url_decode64(b64, padding: false),
         :error <- Base.url_decode64(b64, padding: true),
         :error <- Base.decode64(b64, padding: false) do
      Base.decode64(b64, padding: true)
    else
      {:ok, bin} -> {:ok, bin}
    end
  end

  defp short_id(id) when is_binary(id),
    do: binary_part(id, 0, min(8, byte_size(id)))
end
