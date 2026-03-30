defmodule PkiRaEngine.Api.CsrController do
  @moduledoc """
  Thin controller for CSR-related REST endpoints. Delegates to CsrValidation.
  """

  import Plug.Conn

  alias PkiRaEngine.CsrValidation

  def submit(conn) do
    tenant_id = conn.assigns[:tenant_id]
    with {:ok, csr_pem} <- fetch_param(conn.body_params, "csr_pem"),
         {:ok, cert_profile_id} <- fetch_param(conn.body_params, "cert_profile_id") do
      case CsrValidation.submit_csr(tenant_id, csr_pem, cert_profile_id) do
        {:ok, csr} ->
          # Auto-validate after submit (fire-and-forget style, but inline for now)
          CsrValidation.validate_csr(tenant_id, csr.id)

          case CsrValidation.get_csr(tenant_id, csr.id) do
            {:ok, fresh_csr} -> json_resp(conn, 201, serialize_csr(fresh_csr))
            {:error, _} -> json_resp(conn, 201, serialize_csr(csr))
          end

        {:error, changeset} ->
          unprocessable(conn, format_errors(changeset))
      end
    else
      {:error, missing_field} ->
        unprocessable(conn, "missing required field: #{missing_field}")
    end
  end

  def list(conn) do
    tenant_id = conn.assigns[:tenant_id]
    filters = build_filters(conn.query_params)
    csrs = CsrValidation.list_csrs(tenant_id, filters)

    json_resp(conn, 200, Enum.map(csrs, &serialize_csr/1))
  end

  def show(conn, id) do
    tenant_id = conn.assigns[:tenant_id]
    case CsrValidation.get_csr(tenant_id, id) do
      {:ok, csr} ->
        json_resp(conn, 200, serialize_csr(csr))

      {:error, :not_found} ->
        not_found(conn)
    end
  end

  def approve(conn, id) do
    tenant_id = conn.assigns[:tenant_id]
    with {:ok, reviewer_user_id} <- fetch_param(conn.body_params, "reviewer_user_id") do
      case CsrValidation.approve_csr(tenant_id, id, reviewer_user_id) do
        {:ok, csr} ->
          json_resp(conn, 200, serialize_csr(csr))

        {:error, :not_found} ->
          not_found(conn)

        {:error, reason} ->
          unprocessable(conn, inspect(reason))
      end
    else
      {:error, missing_field} ->
        unprocessable(conn, "missing required field: #{missing_field}")
    end
  end

  def reject(conn, id) do
    tenant_id = conn.assigns[:tenant_id]
    with {:ok, reviewer_user_id} <- fetch_param(conn.body_params, "reviewer_user_id"),
         {:ok, reason} <- fetch_param(conn.body_params, "reason") do
      case CsrValidation.reject_csr(tenant_id, id, reviewer_user_id, reason) do
        {:ok, csr} ->
          json_resp(conn, 200, serialize_csr(csr))

        {:error, :not_found} ->
          not_found(conn)

        {:error, err} ->
          unprocessable(conn, inspect(err))
      end
    else
      {:error, missing_field} ->
        unprocessable(conn, "missing required field: #{missing_field}")
    end
  end

  # -- Private ---------------------------------------------------------------

  defp fetch_param(params, key) do
    case Map.fetch(params, key) do
      {:ok, value} -> {:ok, value}
      :error -> {:error, key}
    end
  end

  defp build_filters(query_params) do
    []
    |> maybe_add_filter(query_params, "status", :status)
    |> maybe_add_filter(query_params, "cert_profile_id", :cert_profile_id)
  end

  defp maybe_add_filter(filters, params, key, filter_key, transform \\ & &1) do
    case Map.get(params, key) do
      nil -> filters
      value -> [{filter_key, transform.(value)} | filters]
    end
  end

  defp serialize_csr(csr) do
    %{
      id: csr.id,
      csr_pem: csr.csr_pem,
      subject_dn: csr.subject_dn,
      status: csr.status,
      cert_profile_id: csr.cert_profile_id,
      submitted_at: csr.submitted_at && DateTime.to_iso8601(csr.submitted_at),
      reviewed_by: csr.reviewed_by,
      reviewed_at: csr.reviewed_at && DateTime.to_iso8601(csr.reviewed_at),
      rejection_reason: csr.rejection_reason,
      issued_cert_serial: csr.issued_cert_serial
    }
  end

  defp format_errors(%Ecto.Changeset{} = changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end

  defp format_errors(error), do: inspect(error)

  defp json_resp(conn, status, body) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(body))
  end

  defp not_found(conn), do: json_resp(conn, 404, %{error: "not_found"})
  defp unprocessable(conn, reason), do: json_resp(conn, 422, %{error: reason})
end
