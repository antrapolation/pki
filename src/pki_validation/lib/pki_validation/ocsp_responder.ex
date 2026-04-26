defmodule PkiValidation.OcspResponder do
  @moduledoc """
  OCSP Responder against Mnesia (RFC 6960 simplified).

  Looks up CertificateStatus in Mnesia and returns one of:
  - `{:ok, %{status: "good"}}` — certificate is active and not expired
  - `{:ok, %{status: "revoked", revoked_at: ..., reason: ...}}` — certificate is revoked
  - `{:ok, %{status: "unknown"}}` — certificate not found

  ## Fail-Closed Signing (RFC 6960 §2.3)

  `signed_response/3` is **fail-closed**: before invoking the signing path it
  calls `KeyActivation.lease_status/1` for the issuer key.  When no active
  lease exists (key not yet activated, lease expired, or ops exhausted) the
  function returns `{:ok, %{status: :try_later, reason: :no_active_lease}}`
  instead of silently falling back to an unsigned response.  Callers should
  relay this as a `tryLater` OCSP response to the relying party per RFC 6960
  §2.3, ensuring the responder never claims to sign while the key is offline.

  PQC signing (KAZ-SIGN, ML-DSA) works transparently through PkiCrypto.
  No separate SigningKeyStore needed — both engines run in the same tenant BEAM.
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

  **Fail-closed**: checks `KeyActivation.lease_status/1` before signing.
  If no active lease exists for `issuer_key_id`, returns
  `{:ok, %{status: :try_later, reason: :no_active_lease}}` (RFC 6960 §2.3).
  The caller must relay this as a `tryLater` response to the relying party.

  When an active lease is present, wraps the signing operation inside
  `KeyActivation.with_lease/2` to atomically decrement `ops_remaining`.

  Options:
    - `:activation_server` — GenServer name/pid for KeyActivation (default: `KeyActivation`)
  """
  def signed_response(serial_number, issuer_key_id, opts \\ []) do
    activation_server = Keyword.get(opts, :activation_server, KeyActivation)
    status = lookup_status(serial_number)

    # Fail-closed: refuse to sign when no active lease exists (RFC 6960 §2.3).
    case KeyActivation.lease_status(activation_server, issuer_key_id) do
      %{active: false} ->
        {:ok, %{status: :try_later, reason: :no_active_lease}}

      %{active: true} ->
        sign_with_active_lease(issuer_key_id, activation_server, serial_number, status)
    end
  end

  # -- Private helpers --

  defp sign_with_active_lease(issuer_key_id, activation_server, serial_number, status) do
    response_data =
      :erlang.term_to_binary(%{
        serial_number: serial_number,
        status: status,
        produced_at: DateTime.utc_now() |> DateTime.to_iso8601()
      })

    # Software keystores: SoftwareAdapter.sign → KeyActivation.with_lease already
    # decrements ops_remaining internally. Wrapping in an outer with_lease causes
    # a GenServer :calling_self deadlock when activation_server is the default
    # KeyActivation process. Call Dispatcher.sign directly for software keys.
    #
    # HSM keystores: Dispatcher.sign → HsmAdapter.sign does NOT call with_lease,
    # so the outer with_lease here is the only ops counter. Keep the wrapper.
    sign_result =
      case Repo.get(IssuerKey, issuer_key_id) do
        {:ok, %IssuerKey{keystore_type: :software}} ->
          case Dispatcher.sign(issuer_key_id, response_data) do
            {:ok, sig} -> {:ok, {:ok, sig}}
            {:error, :not_active} -> {:error, :not_found}
            {:error, reason} -> {:error, reason}
          end

        _ ->
          KeyActivation.with_lease(activation_server, issuer_key_id, fn _handle ->
            Dispatcher.sign(issuer_key_id, response_data)
          end)
      end

    case sign_result do
      {:ok, {:ok, signature}} ->
        finalize_response(issuer_key_id, status, response_data, signature)

      {:ok, {:error, reason}} ->
        {:error, {:signing_failed, reason}}

      {:error, :lease_expired} ->
        {:ok, %{status: :try_later, reason: :no_active_lease}}

      {:error, :ops_exhausted} ->
        {:ok, %{status: :try_later, reason: :no_active_lease}}

      {:error, :not_found} ->
        {:ok, %{status: :try_later, reason: :no_active_lease}}

      {:error, reason} ->
        {:error, {:signing_failed, reason}}
    end
  end

  defp finalize_response(issuer_key_id, status, response_data, signature) do
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
  end

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
