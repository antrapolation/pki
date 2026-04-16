defmodule PkiValidation.Ocsp.DerResponder do
  @moduledoc """
  Orchestrates the DER OCSP request -> response flow against Mnesia.

  1. For each CertID in the request, look up the corresponding
     CertificateStatus in Mnesia (scoped to issuer_key_id).
  2. If an issuer_key_id is provided and a key is active, sign the response
     via KeyActivation.get_active_key/2.
  3. Build SingleResponse entries (good / revoked / unknown).
  4. Hand off to ResponseBuilder.build/4 to produce the signed DER.
  """

  alias PkiValidation.Ocsp.ResponseBuilder
  alias PkiMnesia.{Repo, Structs.CertificateStatus, Structs.IssuerKey}
  alias PkiCaEngine.KeyActivation

  @doc """
  Build a signed OCSP response for the given decoded request.

  `request` is a map shaped like `RequestDecoder.decode/1`'s output:
    `%{cert_ids: [...], nonce: ...}`

  Options:
    - `:issuer_key_id` — ID of the issuer key to use for signing
    - `:activation_server` — GenServer name/pid for KeyActivation (default: `KeyActivation`)
  """
  @spec respond(map(), keyword()) :: {:ok, binary()} | {:error, term()}
  def respond(request, opts \\ [])

  def respond(%{cert_ids: cert_ids, nonce: nonce} = _request, opts) do
    activation_server = Keyword.get(opts, :activation_server, KeyActivation)
    issuer_key_id = Keyword.get(opts, :issuer_key_id)

    try do
      case resolve_signing_key(issuer_key_id, activation_server) do
        {:ok, signing_key} ->
          responses = Enum.map(cert_ids, &lookup_response(&1, issuer_key_id))
          ResponseBuilder.build(:successful, responses, signing_key, nonce: nonce)

        :unauthorized ->
          ResponseBuilder.build(:unauthorized, [], dummy_key())
      end
    rescue
      _ -> ResponseBuilder.build(:internalError, [], dummy_key())
    catch
      _, _ -> ResponseBuilder.build(:internalError, [], dummy_key())
    end
  end

  # -- Private helpers --

  defp resolve_signing_key(nil, _activation_server), do: :unauthorized

  defp resolve_signing_key(issuer_key_id, activation_server) do
    with {:ok, private_key} <- KeyActivation.get_active_key(activation_server, issuer_key_id),
         {:ok, %IssuerKey{} = issuer_key} <- Repo.get(IssuerKey, issuer_key_id),
         true <- not is_nil(issuer_key.certificate_der) do
      signing_key = %{
        algorithm: issuer_key.algorithm,
        private_key: private_key,
        certificate_der: issuer_key.certificate_der
      }
      {:ok, signing_key}
    else
      {:error, :not_active} -> :unauthorized
      {:ok, nil} -> :unauthorized
      false -> :unauthorized
      {:error, _} -> :unauthorized
    end
  end

  defp lookup_response(cert_id, issuer_key_id) do
    serial = to_string(cert_id.serial_number)

    filter_fn = fn cs ->
      cs.serial_number == serial &&
        (is_nil(issuer_key_id) || cs.issuer_key_id == issuer_key_id)
    end

    case Repo.where(CertificateStatus, filter_fn) do
      {:ok, []} ->
        %{
          cert_id: cert_id,
          status: :unknown,
          this_update: DateTime.utc_now(),
          next_update: nil
        }

      {:ok, [%CertificateStatus{status: "active"} | _]} ->
        %{
          cert_id: cert_id,
          status: :good,
          this_update: DateTime.utc_now(),
          next_update: next_update_default()
        }

      {:ok, [%CertificateStatus{status: "revoked"} = c | _]} ->
        %{
          cert_id: cert_id,
          status: {:revoked, c.revoked_at, revocation_reason_to_atom(c.revocation_reason)},
          this_update: DateTime.utc_now(),
          next_update: next_update_default()
        }

      {:ok, [_ | _]} ->
        # Other statuses (suspended, etc.) treated as unknown
        %{
          cert_id: cert_id,
          status: :unknown,
          this_update: DateTime.utc_now(),
          next_update: nil
        }

      {:error, _reason} ->
        %{
          cert_id: cert_id,
          status: :unknown,
          this_update: DateTime.utc_now(),
          next_update: nil
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

  defp dummy_key do
    %{algorithm: "ecc_p256", private_key: <<>>, certificate_der: <<>>}
  end
end
