defmodule PkiRaEngine.Api.CertController do
  @moduledoc """
  Handles certificate query endpoints.

  Certificates in the RA engine are CSRs that have reached "issued" status.
  The full certificate data (DER, PEM, validity) is stored in the CA engine;
  the RA tracks the `issued_cert_serial` linking the CSR to the CA record.
  """

  import Plug.Conn
  import Ecto.Query

  alias PkiRaEngine.TenantRepo
  alias PkiRaEngine.Schema.CsrRequest

  def index(conn) do
    tenant_id = conn.assigns[:tenant_id]
    repo = TenantRepo.ra_repo(tenant_id)
    filters = build_filters(conn.query_params)

    certs =
      CsrRequest
      |> where([c], c.status == "issued")
      |> apply_filters(filters)
      |> order_by([c], desc: c.reviewed_at)
      |> repo.all()
      |> repo.preload(:cert_profile)

    json(conn, 200, Enum.map(certs, &serialize_cert/1))
  end

  def show(conn, serial) do
    tenant_id = conn.assigns[:tenant_id]
    repo = TenantRepo.ra_repo(tenant_id)

    case repo.one(from c in CsrRequest, where: c.issued_cert_serial == ^serial, preload: [:cert_profile]) do
      nil -> json(conn, 404, %{error: "not_found"})
      csr -> json(conn, 200, serialize_cert(csr))
    end
  end

  def revoke(conn, serial) do
    tenant_id = conn.assigns[:tenant_id]
    reason = get_in(conn.body_params, ["reason"]) || "unspecified"

    case PkiRaEngine.CsrValidation.revoke_certificate(tenant_id, serial, reason) do
      {:ok, result} ->
        json(conn, 200, result)

      {:error, {:ca_revocation_failed, status, msg}} ->
        json(conn, status, %{error: "revocation_failed", message: msg})

      {:error, reason} ->
        require Logger
        Logger.error("cert_revocation_failed serial=#{serial} reason=#{inspect(reason)}")
        json(conn, 500, %{error: "revocation_failed"})
    end
  end

  # --- Private ---

  defp build_filters(query_params) do
    []
    |> maybe_filter(:cert_profile_id, query_params["cert_profile_id"])
    |> maybe_filter(:subject_dn, query_params["subject_dn"])
  end

  defp maybe_filter(filters, _key, nil), do: filters
  defp maybe_filter(filters, _key, ""), do: filters
  defp maybe_filter(filters, key, value), do: [{key, value} | filters]

  defp apply_filters(query, []), do: query

  defp apply_filters(query, [{:cert_profile_id, id} | rest]) do
    query |> where([c], c.cert_profile_id == ^id) |> apply_filters(rest)
  end

  defp apply_filters(query, [{:subject_dn, dn} | rest]) do
    escaped = dn |> String.replace("\\", "\\\\") |> String.replace("%", "\\%") |> String.replace("_", "\\_")
    pattern = "%#{escaped}%"
    query |> where([c], ilike(c.subject_dn, ^pattern)) |> apply_filters(rest)
  end

  defp apply_filters(query, [_ | rest]), do: apply_filters(query, rest)

  defp serialize_cert(csr) do
    %{
      id: csr.id,
      issued_cert_serial: csr.issued_cert_serial,
      subject_dn: csr.subject_dn,
      status: csr.status,
      cert_profile_id: csr.cert_profile_id,
      cert_profile_name: profile_name(csr.cert_profile),
      submitted_at: csr.submitted_at && DateTime.to_iso8601(csr.submitted_at),
      reviewed_by: csr.reviewed_by,
      reviewed_at: csr.reviewed_at && DateTime.to_iso8601(csr.reviewed_at)
    }
  end

  defp profile_name(nil), do: nil
  defp profile_name(profile), do: profile.name

  defp json(conn, status, body) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(body))
  end
end
