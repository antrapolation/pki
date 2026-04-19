defmodule PkiValidation.OcspResponder do
  @moduledoc """
  OCSP Responder against Mnesia (RFC 6960 simplified).

  Looks up CertificateStatus in Mnesia and returns one of:
  - `{:ok, %{status: "good"}}` — certificate is active and not expired
  - `{:ok, %{status: "revoked", revoked_at: ..., reason: ...}}` — certificate is revoked
  - `{:ok, %{status: "unknown"}}` — certificate not found

  For signed responses, calls `PkiCaEngine.KeyActivation.get_active_key/2` directly.
  No separate SigningKeyStore needed — both engines run in the same tenant BEAM.

  PQC signing (KAZ-SIGN, ML-DSA) works transparently through PkiCrypto.
  """

  alias PkiMnesia.{Repo, Structs.CertificateStatus, Structs.IssuerKey}
  alias PkiCaEngine.{KeyActivation, KeyStore.Dispatcher}

  @doc """
  Check the status of a certificate by its serial number.
  Always does a fresh Mnesia lookup (no ETS cache in this architecture —
  Mnesia is already in-memory).
  """
  def check_status(serial_number) do
    {:ok, lookup_status(serial_number)}
  end

  @doc """
  Build a signed OCSP response for the given serial number.

  Uses the issuer's active key (retrieved via KeyActivation) to sign the
  response. If the key is not active (e.g. in dev/test without ceremony),
  returns an unsigned response with `unsigned: true`.

  Options:
    - `:activation_server` — GenServer name/pid for KeyActivation (default: `KeyActivation`)
  """
  def signed_response(serial_number, issuer_key_id, opts \\ []) do
    _activation_server = Keyword.get(opts, :activation_server, KeyActivation)
    status = lookup_status(serial_number)

    response_data = :erlang.term_to_binary(%{
      serial_number: serial_number,
      status: status,
      produced_at: DateTime.utc_now() |> DateTime.to_iso8601()
    })

    case Dispatcher.sign(issuer_key_id, response_data) do
      {:ok, signature} ->
        case Repo.get(IssuerKey, issuer_key_id) do
          {:ok, %IssuerKey{} = issuer_key} ->
            {:ok, %{
              status: status,
              response_data: response_data,
              signature: signature,
              algorithm: issuer_key.algorithm
            }}

          {:ok, nil} ->
            # Issuer key not in Mnesia — return unsigned status
            {:ok, %{status: status, unsigned: true}}

          {:error, reason} ->
            {:error, {:issuer_key_lookup_failed, reason}}
        end

      {:error, :not_active} ->
        # Key not yet activated via threshold ceremony — return unsigned status
        {:ok, %{status: status, unsigned: true}}

      {:error, :agent_not_connected} ->
        # Remote HSM agent not connected — return unsigned status
        {:ok, %{status: status, unsigned: true}}

      {:error, :issuer_key_not_found} ->
        # Issuer key not in Mnesia — return unsigned status
        {:ok, %{status: status, unsigned: true}}

      {:error, reason} ->
        {:error, {:signing_failed, reason}}
    end
  end

  # -- Private helpers --

  defp lookup_status(serial_number) do
    case Repo.get_all_by_index(CertificateStatus, :serial_number, serial_number) do
      {:ok, []} ->
        %{status: "unknown"}

      {:ok, [%CertificateStatus{status: "revoked"} = cert | _]} ->
        %{
          status: "revoked",
          revoked_at: cert.revoked_at,
          reason: cert.revocation_reason,
          serial_number: cert.serial_number
        }

      {:ok, [%CertificateStatus{status: "active"} = cert | _]} ->
        now = DateTime.utc_now()

        if cert.not_after && DateTime.compare(now, cert.not_after) != :lt do
          %{
            status: "revoked",
            revoked_at: cert.not_after,
            reason: "certificate_expired",
            serial_number: cert.serial_number
          }
        else
          %{status: "good", serial_number: cert.serial_number, not_after: cert.not_after}
        end

      {:ok, [%CertificateStatus{} | _]} ->
        # Any other status (suspended, etc.) treated as unknown
        %{status: "unknown"}

      {:error, _reason} ->
        %{status: "unknown"}
    end
  end

end
