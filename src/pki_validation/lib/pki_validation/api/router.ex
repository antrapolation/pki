defmodule PkiValidation.Api.Router do
  @moduledoc """
  HTTP router for the PKI Validation service.

  Endpoints:
  - GET  /health           — health check
  - POST /ocsp             — OCSP status query (simplified JSON)
  - GET  /crl              — current CRL
  - POST /notify/issuance  — CA notifies of new certificate (internal, authenticated)
  - POST /notify/revocation — CA notifies of certificate revocation (internal, authenticated)
  """

  use Plug.Router

  require Logger

  alias PkiValidation.Repo
  alias PkiValidation.Schema.CertificateStatus
  alias PkiValidation.OcspCache

  import Ecto.Query

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
              Logger.info("Certificate revocation recorded: serial=#{serial_number} reason=#{reason}")
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
      {serial, reason} when is_binary(serial) and serial != "" and is_binary(reason) and reason != "" ->
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

  defp format_changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
