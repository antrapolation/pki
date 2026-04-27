defmodule PkiValidation.Ocsp.DerResponder do
  @moduledoc """
  Orchestrates the DER OCSP request -> response flow against Mnesia.

  1. For each CertID in the request, look up the corresponding
     CertificateStatus in Mnesia (scoped to issuer_key_id).
  2. If an issuer_key_id is provided and a key is active, sign the response
     via KeyActivation.lease_status/2 + KeyActivation.with_lease/3.
  3. Build SingleResponse entries (good / revoked / unknown).
  4. Hand off to ResponseBuilder.build/4 to produce the signed DER.

  ## RFC 6960 §2.3 compliance

  When no active lease is held for the signing key the responder returns
  `tryLater` (not `unauthorized`).  `unauthorized` signals a **permanent**
  refusal and causes strict PKIX stacks to break the certificate chain.
  `tryLater` correctly signals **temporary** unavailability, allowing
  validators to retry later.
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
    error_key = dummy_key()

    try do
      case resolve_signing_key(issuer_key_id, activation_server, cert_ids, nonce) do
        {:ok, der} ->
          {:ok, der}

        :try_later ->
          ResponseBuilder.build(:tryLater, [], error_key, nonce: nonce)

        :unauthorized ->
          ResponseBuilder.build(:unauthorized, [], error_key, nonce: nonce)
      end
    rescue
      _ -> ResponseBuilder.build(:internalError, [], error_key, nonce: nonce)
    catch
      _, _ -> ResponseBuilder.build(:internalError, [], error_key, nonce: nonce)
    end
  end

  # -- Private helpers --

  # No issuer_key_id supplied → the request itself is malformed/unauthorized
  defp resolve_signing_key(nil, _activation_server, _cert_ids, _nonce), do: :unauthorized

  # RFC 6960 §2.3: check lease status before attempting to sign.
  # If the lease is inactive (not yet activated, expired, or ops-exhausted),
  # return :try_later so the caller emits a `tryLater` response — NOT
  # `unauthorized`, which would signal permanent refusal to validators.
  defp resolve_signing_key(issuer_key_id, activation_server, cert_ids, nonce) do
    case KeyActivation.lease_status(activation_server, issuer_key_id) do
      %{active: false} ->
        :try_later

      %{active: true} ->
        build_signed_response(issuer_key_id, activation_server, cert_ids, nonce)
    end
  end

  defp build_signed_response(issuer_key_id, activation_server, cert_ids, nonce) do
    responses = Enum.map(cert_ids, &lookup_response(&1, issuer_key_id))

    lease_result =
      KeyActivation.with_lease(activation_server, issuer_key_id, fn handle ->
        with {:ok, %IssuerKey{} = issuer_key} <- Repo.get(IssuerKey, issuer_key_id),
             false <- is_nil(issuer_key.certificate_der) do
          signing_key = %{
            algorithm: issuer_key.algorithm,
            private_key: handle,
            certificate_der: issuer_key.certificate_der
          }

          ResponseBuilder.build(:successful, responses, signing_key, nonce: nonce)
        else
          {:ok, nil} -> {:error, :issuer_key_not_found}
          true -> {:error, :no_certificate}
          {:error, reason} -> {:error, reason}
        end
      end)

    case lease_result do
      {:ok, build_result} ->
        # build_result is the return of the fun passed to with_lease
        build_result

      {:error, :lease_expired} ->
        :try_later

      {:error, :ops_exhausted} ->
        :try_later

      {:error, :not_found} ->
        :try_later

      {:error, _reason} ->
        ResponseBuilder.build(:internalError, [], dummy_key(), nonce: nonce)
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

  @secp256r1_oid {1, 2, 840, 10045, 3, 1, 7}

  # Generates an ephemeral P-256 key+cert for signing error responses that carry
  # an OCSP nonce. RFC 6960 §4.4.1 requires the nonce to be echoed in all
  # responses, including error statuses. The client cannot verify this signature
  # (the cert is anonymous), but the nonce bytes will be present in the DER.
  defp dummy_key do
    {pub, priv} = :crypto.generate_key(:ecdh, :secp256r1)

    ec_priv_record =
      {:ECPrivateKey, 1, priv, {:namedCurve, @secp256r1_oid}, pub, :asn1_NOVALUE}

    %{cert: cert_der} =
      :public_key.pkix_test_root_cert(~c"OCSP Error Responder", [{:key, ec_priv_record}])

    priv_der = :public_key.der_encode(:ECPrivateKey, ec_priv_record)

    %{algorithm: "ECC-P256", private_key: priv_der, certificate_der: cert_der}
  end
end
