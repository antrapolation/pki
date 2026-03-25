defmodule PkiCaEngine.Api.CertificateController do
  @moduledoc """
  Handles certificate signing, revocation, and query endpoints.
  """

  import Plug.Conn
  alias PkiCaEngine.CertificateSigning

  def index(conn) do
    case conn.query_params do
      %{"issuer_key_id" => issuer_key_id_str} ->
        issuer_key_id = String.to_integer(issuer_key_id_str)
        filters = build_filters(conn.query_params)
        certs = CertificateSigning.list_certificates(issuer_key_id, filters)
        json(conn, 200, %{data: Enum.map(certs, &serialize_certificate/1)})

      _ ->
        json(conn, 400, %{error: "bad_request", message: "issuer_key_id query param required"})
    end
  end

  def show(conn, serial) do
    case CertificateSigning.get_certificate(serial) do
      {:ok, cert} -> json(conn, 200, serialize_certificate(cert))
      {:error, :not_found} -> json(conn, 404, %{error: "not_found"})
    end
  end

  def sign(conn) do
    with %{
           "issuer_key_id" => issuer_key_id,
           "csr_pem" => csr_pem
         } <- conn.body_params do
      cert_profile = conn.body_params["cert_profile"] || %{}

      profile_map =
        %{}
        |> maybe_put(:validity_days, cert_profile["validity_days"])
        |> maybe_put(:subject_dn, cert_profile["subject_dn"])
        |> maybe_put(:id, cert_profile["id"])

      case CertificateSigning.sign_certificate(issuer_key_id, csr_pem, profile_map) do
        {:ok, cert} ->
          json(conn, 201, serialize_certificate(cert))

        {:error, :key_not_active} ->
          json(conn, 422, %{error: "key_not_active", message: "issuer key is not active"})

        {:error, :issuer_key_not_found} ->
          json(conn, 404, %{error: "not_found", message: "issuer key not found"})

        {:error, reason} ->
          json(conn, 500, %{error: "signing_failed", message: inspect(reason)})
      end
    else
      _ ->
        json(conn, 400, %{error: "bad_request", message: "issuer_key_id and csr_pem required"})
    end
  end

  def revoke(conn) do
    with %{"serial_number" => serial, "reason" => reason} <- conn.body_params do
      case CertificateSigning.revoke_certificate(serial, reason) do
        {:ok, cert} ->
          json(conn, 200, serialize_certificate(cert))

        {:error, :not_found} ->
          json(conn, 404, %{error: "not_found"})

        {:error, reason} ->
          json(conn, 500, %{error: "revocation_failed", message: inspect(reason)})
      end
    else
      _ ->
        json(conn, 400, %{error: "bad_request", message: "serial_number and reason required"})
    end
  end

  defp build_filters(params) do
    []
    |> maybe_add_filter(:status, params["status"])
  end

  defp maybe_add_filter(filters, _key, nil), do: filters
  defp maybe_add_filter(filters, key, value), do: [{key, value} | filters]

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp serialize_certificate(cert) do
    %{
      id: cert.id,
      serial_number: cert.serial_number,
      subject_dn: cert.subject_dn,
      cert_pem: cert.cert_pem,
      not_before: cert.not_before,
      not_after: cert.not_after,
      status: cert.status,
      revoked_at: cert.revoked_at,
      revocation_reason: cert.revocation_reason,
      issuer_key_id: cert.issuer_key_id,
      inserted_at: cert.inserted_at,
      updated_at: cert.updated_at
    }
  end

  defp json(conn, status, body) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(body))
  end
end
