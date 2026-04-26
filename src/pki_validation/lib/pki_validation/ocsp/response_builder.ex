defmodule PkiValidation.Ocsp.ResponseBuilder do
  @moduledoc """
  Builds and signs RFC 6960 `OCSPResponse` messages.

  Because the local `OCSP.asn1` schema declares `AlgorithmIdentifier`,
  `Certificate`, `Name`, and `Extensions` as `ANY`, this module
  pre-encodes every one of those fields as DER before handing the
  record to `:OCSP.encode/2`:

    * `AlgorithmIdentifier` values are hand-rolled fixed DER blobs
      (there are only a handful we care about).
    * The responder's certificate is passed through as its raw DER
      bytes (the compiled module happily accepts `[der_binary]` for
      `SEQUENCE OF Certificate` when `Certificate ::= ANY`).
    * The responder's `Name` for `ResponderID byName` is re-encoded
      via `:public_key.der_encode/2`, which knows the real PKIX
      `Name` schema.
    * `responseExtensions` (e.g. the echoed OCSP nonce) are
      pre-encoded via `:public_key.der_encode(:Extensions, ...)`.

  The module supports the full `OCSPResponseStatus` enum; only
  `:successful` carries a signed `BasicOCSPResponse`, the error
  statuses produce a bare `OCSPResponse` with no `responseBytes`.
  """

  @basic_ocsp_oid {1, 3, 6, 1, 5, 5, 7, 48, 1, 1}
  @nonce_oid {1, 3, 6, 1, 5, 5, 7, 48, 1, 2}

  # AlgorithmIdentifier DER blob for SHA-1 — used in CertID records (RFC 6960).
  # Per-signer AlgorithmIdentifier blobs now live in the signer modules
  # (`PkiValidation.Crypto.Signer.*.algorithm_identifier_der/0`).
  @sha1_alg_der <<0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00>>

  @error_statuses [
    :malformedRequest,
    :internalError,
    :tryLater,
    :sigRequired,
    :unauthorized
  ]

  @type status ::
          :successful
          | :malformedRequest
          | :internalError
          | :tryLater
          | :sigRequired
          | :unauthorized

  @type cert_status ::
          :good
          | :unknown
          | {:revoked, DateTime.t(), atom()}

  @type response_entry :: %{
          cert_id: %{
            issuer_name_hash: binary(),
            issuer_key_hash: binary(),
            serial_number: integer()
          },
          status: cert_status(),
          this_update: DateTime.t(),
          next_update: DateTime.t() | nil
        }

  # Two valid shapes:
  #   1. SigningKeyStore path — pre-resolved signer module (algorithm strings like "ecc_p256")
  #   2. DerResponder / IssuerKey path — algorithm string resolved at sign time via PkiCrypto
  #      (algorithm strings like "ECC-P256", "ML-DSA-65")
  @type signing_key ::
          %{signer: module(), private_key: binary(), certificate_der: binary()}
          | %{algorithm: String.t(), private_key: binary(), certificate_der: binary()}

  @doc """
  Build a DER-encoded `OCSPResponse`.

  For `:successful`, `responses` is a list of per-certificate
  response entries and a signed `BasicOCSPResponse` is produced.
  For any error status the `responses` list is ignored and an
  `OCSPResponse` with no `responseBytes` is returned.
  """
  @spec build(status(), [response_entry()], signing_key(), keyword()) ::
          {:ok, binary()} | {:error, term()}
  def build(status, responses, signing_key, opts \\ [])

  def build(:successful, responses, signing_key, opts) when is_list(responses) do
    try do
      nonce = Keyword.get(opts, :nonce)

      basic_der = build_basic_response(responses, signing_key, nonce)

      response_bytes = {:ResponseBytes, @basic_ocsp_oid, basic_der}
      ocsp_response = {:OCSPResponse, :successful, response_bytes}

      {:ok, iodata} = :OCSP.encode(:OCSPResponse, ocsp_response)
      {:ok, IO.iodata_to_binary(iodata)}
    rescue
      e -> {:error, e}
    catch
      kind, reason -> {:error, {kind, reason}}
    end
  end

  def build(status, _responses, _signing_key, _opts) when status in @error_statuses do
    try do
      ocsp_response = {:OCSPResponse, status, :asn1_NOVALUE}
      {:ok, iodata} = :OCSP.encode(:OCSPResponse, ocsp_response)
      {:ok, IO.iodata_to_binary(iodata)}
    rescue
      e -> {:error, e}
    catch
      kind, reason -> {:error, {kind, reason}}
    end
  end

  # ---- BasicOCSPResponse construction ----

  defp build_basic_response(responses, signing_key, nonce) do
    responder_id = build_responder_id(signing_key.certificate_der)
    produced_at = generalized_time(DateTime.utc_now())
    single_responses = Enum.map(responses, &build_single_response/1)
    response_extensions = build_response_extensions(nonce)

    response_data =
      {:ResponseData, :v1, responder_id, produced_at, single_responses, response_extensions}

    {:ok, tbs_iodata} = :OCSP.encode(:ResponseData, response_data)
    tbs_bin = IO.iodata_to_binary(tbs_iodata)

    {sig_alg_der, signature} = sign_tbs(tbs_bin, signing_key)

    certs = [signing_key.certificate_der]

    basic = {:BasicOCSPResponse, response_data, sig_alg_der, signature, certs}
    {:ok, basic_iodata} = :OCSP.encode(:BasicOCSPResponse, basic)
    IO.iodata_to_binary(basic_iodata)
  end

  defp build_single_response(
         %{
           cert_id: cert_id,
           status: status,
           this_update: this_update
         } = entry
       ) do
    next_update = Map.get(entry, :next_update)

    cert_id_record =
      {:CertID, @sha1_alg_der, cert_id.issuer_name_hash, cert_id.issuer_key_hash,
       cert_id.serial_number}

    cert_status = build_cert_status(status)

    next_update_value =
      case next_update do
        nil -> :asn1_NOVALUE
        %DateTime{} = dt -> generalized_time(dt)
      end

    {:SingleResponse, cert_id_record, cert_status, generalized_time(this_update),
     next_update_value, :asn1_NOVALUE}
  end

  defp build_cert_status(:good), do: {:good, :NULL}
  defp build_cert_status(:unknown), do: {:unknown, :NULL}

  defp build_cert_status({:revoked, %DateTime{} = when_dt, reason}) do
    revoked_info = {:RevokedInfo, generalized_time(when_dt), reason}
    {:revoked, revoked_info}
  end

  defp build_cert_status({:revoked, %DateTime{} = when_dt}) do
    revoked_info = {:RevokedInfo, generalized_time(when_dt), :asn1_NOVALUE}
    {:revoked, revoked_info}
  end

  # ---- ResponderID ----

  defp build_responder_id(cert_der) when is_binary(cert_der) do
    otp_cert = :public_key.pkix_decode_cert(cert_der, :otp)
    # {:OTPCertificate, tbs, sigAlg, sig}
    tbs = :erlang.element(2, otp_cert)
    # OTPTBSCertificate fields (1-indexed):
    # 1 = :OTPTBSCertificate
    # 2 = version
    # 3 = serialNumber
    # 4 = signature
    # 5 = issuer
    # 6 = validity
    # 7 = subject
    subject = :erlang.element(7, tbs)
    name_der = :public_key.der_encode(:Name, subject)
    {:byName, name_der}
  end

  # ---- Response Extensions ----

  defp build_response_extensions(nil), do: :asn1_NOVALUE

  defp build_response_extensions(nonce) when is_binary(nonce) do
    inner = wrap_octet_string(nonce)
    :public_key.der_encode(:Extensions, [{:Extension, @nonce_oid, false, inner}])
  end

  defp wrap_octet_string(bin) when byte_size(bin) <= 127 do
    <<0x04, byte_size(bin)::8, bin::binary>>
  end

  defp wrap_octet_string(bin) when byte_size(bin) <= 255 do
    <<0x04, 0x81, byte_size(bin)::8, bin::binary>>
  end

  defp wrap_octet_string(bin) do
    <<0x04, 0x82, byte_size(bin)::16, bin::binary>>
  end

  # ---- GeneralizedTime ----

  defp generalized_time(%DateTime{} = dt) do
    # Assumes UTC (DateTime.utc_now/0 always is). Do NOT call
    # shift_zone!/2 — it pulls in tzdata unnecessarily.
    dt
    |> Calendar.strftime("%Y%m%d%H%M%SZ")
    |> String.to_charlist()
  end

  # ---- Signing ----

  # Shape 1 — SigningKeyStore path: signer module pre-resolved at config load time.
  defp sign_tbs(tbs, %{signer: signer_mod, private_key: priv}) do
    signature = signer_mod.sign(tbs, priv)
    {signer_mod.algorithm_identifier_der(), signature}
  end

  # Shape 2 — IssuerKey / DerResponder path: algorithm string resolved at sign time
  # via PkiCrypto. Algorithm strings use the PkiCrypto format ("ECC-P256", "ML-DSA-65").
  #
  # Key format for private_key:
  #   ECC / RSA   — DER-encoded :ECPrivateKey / :RSAPrivateKey (same as SoftwareAdapter)
  #   PQC         — raw NIF bytes
  #
  # AlgorithmIdentifier is sourced from Signer modules (pre-encoded DER blobs)
  # via @pki_to_signer_alg, because OCSP's BasicOCSPResponse declares signatureAlgorithm
  # as ANY — the OCSP codec requires a binary, not a tuple.
  @pki_to_signer_alg %{
    "ECC-P256"     => "ecc_p256",
    "ECC-P384"     => "ecc_p384",
    "RSA-2048"     => "rsa2048",
    "RSA-4096"     => "rsa4096",
    "ML-DSA-44"    => "ml_dsa_44",
    "ML-DSA-65"    => "ml_dsa_65",
    "ML-DSA-87"    => "ml_dsa_87",
    "KAZ-SIGN-128" => "kaz_sign_128",
    "KAZ-SIGN-192" => "kaz_sign_192",
    "KAZ-SIGN-256" => "kaz_sign_256"
  }

  defp sign_tbs(tbs, %{algorithm: algorithm, private_key: priv}) do
    signer_mod =
      case PkiValidation.Crypto.Signer.Registry.fetch(@pki_to_signer_alg[algorithm] || "") do
        {:ok, mod} -> mod
        :error -> raise "no signer registered for algorithm: #{inspect(algorithm)}"
      end

    signature =
      case PkiCrypto.AlgorithmRegistry.by_id(algorithm) do
        {:ok, %{family: family}} when family in [:ml_dsa, :kaz_sign, :slh_dsa] ->
          algo = PkiCrypto.Registry.get(algorithm)
          {:ok, sig} = PkiCrypto.Algorithm.sign(algo, priv, tbs)
          sig

        {:ok, %{family: :ecdsa}} ->
          hash = if algorithm == "ECC-P384", do: :sha384, else: :sha256
          native_key = :public_key.der_decode(:ECPrivateKey, priv)
          :public_key.sign(tbs, hash, native_key)

        {:ok, %{family: :rsa}} ->
          native_key = :public_key.der_decode(:RSAPrivateKey, priv)
          :public_key.sign(tbs, :sha256, native_key)

        _ ->
          raise "unknown algorithm for OCSP signing: #{inspect(algorithm)}"
      end

    {signer_mod.algorithm_identifier_der(), signature}
  end
end
