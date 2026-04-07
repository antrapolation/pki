defmodule PkiValidation.Ocsp.DerResponder do
  @moduledoc """
  Orchestrates the DER OCSP request -> response flow.

  1. Match the request's `issuer_key_hash` against a loaded signing key
     in `SigningKeyStore`. If no match, return an `:unauthorized` response.
  2. For each `CertID` in the request, look up the corresponding
     `certificate_status` row scoped to that issuer.
  3. Build SingleResponse entries (good / revoked / unknown).
  4. Hand off to `ResponseBuilder.build/4` to produce the signed DER.
  """

  alias PkiValidation.Ocsp.ResponseBuilder
  alias PkiValidation.Repo
  alias PkiValidation.Schema.CertificateStatus
  alias PkiValidation.SigningKeyStore

  import Ecto.Query

  @doc """
  Build a signed OCSP response for the given decoded request.

    * `request` is a map shaped like `RequestDecoder.decode/1`'s output:
      `%{cert_ids: [%{issuer_name_hash, issuer_key_hash, serial_number}], nonce: ...}`
    * `opts` may contain `:signing_key_store` (defaults to `SigningKeyStore`)

  Returns `{:ok, der_binary}`.
  """
  @spec respond(map(), keyword()) :: {:ok, binary()} | {:error, term()}
  def respond(request, opts \\ [])

  def respond(%{cert_ids: cert_ids, nonce: nonce} = _request, opts) do
    store = Keyword.get(opts, :signing_key_store, SigningKeyStore)

    try do
      case resolve_signing_key(cert_ids, store) do
        {:ok, signing_key, issuer_key_id} ->
          responses = Enum.map(cert_ids, &lookup_response(&1, issuer_key_id))
          ResponseBuilder.build(:successful, responses, signing_key, nonce: nonce)

        :unauthorized ->
          ResponseBuilder.build(:unauthorized, [], dummy_key(), nonce: nonce)
      end
    rescue
      _ -> ResponseBuilder.build(:internalError, [], dummy_key(), nonce: nonce)
    catch
      _, _ -> ResponseBuilder.build(:internalError, [], dummy_key(), nonce: nonce)
    end
  end

  # ---- Private ----

  defp resolve_signing_key([], _store), do: :unauthorized

  defp resolve_signing_key([first | _rest], store) do
    case SigningKeyStore.find_by_key_hash(store, first.issuer_key_hash) do
      {:ok, signing_key, issuer_key_id} -> {:ok, signing_key, issuer_key_id}
      :not_found -> :unauthorized
    end
  end

  defp lookup_response(cert_id, issuer_key_id) do
    serial = to_string(cert_id.serial_number)

    query =
      from c in CertificateStatus,
        where: c.issuer_key_id == ^issuer_key_id and c.serial_number == ^serial

    case Repo.one(query) do
      nil ->
        %{
          cert_id: cert_id,
          status: :unknown,
          this_update: DateTime.utc_now(),
          next_update: nil
        }

      %CertificateStatus{status: "active"} ->
        %{
          cert_id: cert_id,
          status: :good,
          this_update: DateTime.utc_now(),
          next_update: next_update_default()
        }

      %CertificateStatus{status: "revoked"} = c ->
        %{
          cert_id: cert_id,
          status: {:revoked, c.revoked_at, revocation_reason_to_atom(c.revocation_reason)},
          this_update: DateTime.utc_now(),
          next_update: next_update_default()
        }
    end
  end

  defp next_update_default, do: DateTime.add(DateTime.utc_now(), 3600, :second)

  defp revocation_reason_to_atom("key_compromise"), do: :keyCompromise
  defp revocation_reason_to_atom("ca_compromise"), do: :cACompromise
  defp revocation_reason_to_atom("affiliation_changed"), do: :affiliationChanged
  defp revocation_reason_to_atom("superseded"), do: :superseded
  defp revocation_reason_to_atom("cessation_of_operation"), do: :cessationOfOperation
  defp revocation_reason_to_atom("certificate_hold"), do: :certificateHold
  defp revocation_reason_to_atom("remove_from_crl"), do: :removeFromCRL
  defp revocation_reason_to_atom("privilege_withdrawn"), do: :privilegeWithdrawn
  defp revocation_reason_to_atom("aa_compromise"), do: :aACompromise
  defp revocation_reason_to_atom(_), do: :unspecified

  # The error builder doesn't actually sign anything but the build/4 signature
  # requires a signing_key argument. Pass an empty placeholder for the error path.
  defp dummy_key do
    %{algorithm: "ecc_p256", private_key: <<>>, certificate_der: <<>>}
  end
end
