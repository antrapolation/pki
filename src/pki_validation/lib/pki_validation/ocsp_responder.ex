defmodule PkiValidation.OcspResponder do
  @moduledoc """
  OCSP Responder (RFC 6960 simplified).

  Checks certificate status by serial number, returning one of:
  - `{:ok, %{status: "good"}}` — certificate is active and not expired
  - `{:ok, %{status: "revoked", revoked_at: ..., reason: ...}}` — certificate is revoked
  - `{:ok, %{status: "unknown"}}` — certificate not found
  """

  alias PkiValidation.OcspCache
  alias PkiValidation.Repo
  alias PkiValidation.Schema.CertificateStatus

  import Ecto.Query

  @doc """
  Check the status of a certificate by its serial number.

  Uses the ETS cache for fast lookups, falling back to the database.
  """
  def check_status(serial_number) do
    case OcspCache.get(serial_number) do
      {:ok, cached_response} ->
        {:ok, cached_response}

      :miss ->
        response = lookup_status(serial_number)

        if response.status in ["good", "revoked"] do
          OcspCache.put(serial_number, response)
        end

        {:ok, response}
    end
  end

  @doc """
  Check status without using the cache (direct database lookup).
  """
  def check_status_uncached(serial_number) do
    {:ok, lookup_status(serial_number)}
  end

  defp lookup_status(serial_number) do
    query =
      from cs in CertificateStatus,
        where: cs.serial_number == ^serial_number

    case Repo.one(query) do
      nil ->
        %{status: "unknown"}

      %CertificateStatus{status: "revoked"} = cert ->
        %{
          status: "revoked",
          revoked_at: cert.revoked_at,
          reason: cert.revocation_reason,
          serial_number: cert.serial_number
        }

      %CertificateStatus{status: "active"} = cert ->
        now = DateTime.utc_now()
        if cert.not_after && DateTime.compare(now, cert.not_after) != :lt do
          %{
            status: "revoked",
            revoked_at: cert.not_after,
            reason: "certificate_expired",
            serial_number: cert.serial_number
          }
        else
          %{
            status: "good",
            serial_number: cert.serial_number,
            not_after: cert.not_after
          }
        end
    end
  end
end
