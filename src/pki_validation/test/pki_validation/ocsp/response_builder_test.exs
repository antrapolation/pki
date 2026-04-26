defmodule PkiValidation.Ocsp.ResponseBuilderTest do
  use ExUnit.Case, async: true

  alias PkiValidation.Ocsp.ResponseBuilder

  @secp256r1_oid {1, 2, 840, 10045, 3, 1, 7}
  @secp384r1_oid {1, 3, 132, 0, 34}
  @nonce_oid {1, 3, 6, 1, 5, 5, 7, 48, 1, 2}

  setup do
    # pkix_test_root_cert generates a self-signed cert AND returns the matching
    # private key. Use BOTH so the signature we later embed in the response is
    # verifiable against the public key extracted from the cert (which is what
    # real OCSP clients do). The default curve is not P-256, so we pass an
    # explicit P-256 private key in via the :key option.
    {pub, priv} = :crypto.generate_key(:ecdh, :secp256r1)

    provided_key =
      {:ECPrivateKey, 1, priv, {:namedCurve, @secp256r1_oid}, pub, :asn1_NOVALUE}

    %{cert: cert_der, key: ec_priv_key_record} =
      :public_key.pkix_test_root_cert(~c"Test Responder", [{:key, provided_key}])

    # ec_priv_key_record is an :ECPrivateKey tuple. Extract the raw scalar for
    # storage in the signing_key map (the responder builder constructs the
    # ECPrivateKey wrapper at sign time from this raw bytes form).
    {:ECPrivateKey, _v, priv_scalar, _curve, pub_point_raw, _attrs} = ec_priv_key_record

    pub_point = resolve_pub_point(pub_point_raw, cert_der)

    signing_key = %{
      algorithm: "ecc_p256",
      signer: PkiValidation.Crypto.Signer.EcdsaP256,
      private_key: PkiValidation.Crypto.Signer.EcdsaP256.decode_private_key(priv_scalar),
      public_key: pub_point,
      certificate_der: cert_der
    }

    cert_id = %{
      issuer_name_hash: :crypto.strong_rand_bytes(20),
      issuer_key_hash: :crypto.strong_rand_bytes(20),
      serial_number: 12345
    }

    {:ok, signing_key: signing_key, cert_id: cert_id}
  end

  test "builds and signs a 'good' response", %{signing_key: key, cert_id: cert_id} do
    response = %{
      cert_id: cert_id,
      status: :good,
      this_update: DateTime.utc_now(),
      next_update: DateTime.add(DateTime.utc_now(), 3600, :second)
    }

    assert {:ok, der} = ResponseBuilder.build(:successful, [response], key, nonce: nil)
    assert is_binary(der)

    assert {:ok, {:OCSPResponse, status, response_bytes}} = :OCSP.decode(:OCSPResponse, der)
    assert status == :successful
    assert response_bytes != :asn1_NOVALUE

    # Decode inner CertStatus to prove it's actually :good (not silently remapped).
    assert match?({:good, _}, decode_first_cert_status(der))
  end

  test "builds a 'revoked' response with reason", %{signing_key: key, cert_id: cert_id} do
    response = %{
      cert_id: cert_id,
      status: {:revoked, DateTime.utc_now(), :keyCompromise},
      this_update: DateTime.utc_now(),
      next_update: nil
    }

    assert {:ok, der} = ResponseBuilder.build(:successful, [response], key, nonce: nil)
    assert is_binary(der)
    assert {:ok, {:OCSPResponse, :successful, _}} = :OCSP.decode(:OCSPResponse, der)

    assert match?(
             {:revoked, {:RevokedInfo, _when, :keyCompromise}},
             decode_first_cert_status(der)
           )
  end

  test "builds an 'unknown' response", %{signing_key: key, cert_id: cert_id} do
    response = %{
      cert_id: cert_id,
      status: :unknown,
      this_update: DateTime.utc_now(),
      next_update: nil
    }

    assert {:ok, der} = ResponseBuilder.build(:successful, [response], key, nonce: nil)
    assert is_binary(der)
    assert {:ok, {:OCSPResponse, :successful, _}} = :OCSP.decode(:OCSPResponse, der)

    assert match?({:unknown, _}, decode_first_cert_status(der))
  end

  test "builds a malformedRequest error response with no signed body", %{signing_key: key} do
    assert {:ok, der} = ResponseBuilder.build(:malformedRequest, [], key, nonce: nil)
    assert is_binary(der)
    {:ok, {:OCSPResponse, status, body}} = :OCSP.decode(:OCSPResponse, der)
    assert status == :malformedRequest
    assert body == :asn1_NOVALUE
  end

  test "builds an unauthorized error response", %{signing_key: key} do
    assert {:ok, der} = ResponseBuilder.build(:unauthorized, [], key, nonce: nil)
    {:ok, {:OCSPResponse, :unauthorized, :asn1_NOVALUE}} = :OCSP.decode(:OCSPResponse, der)
  end

  test "echoes nonce bytes exactly when provided", %{signing_key: key, cert_id: cert_id} do
    nonce = :crypto.strong_rand_bytes(16)

    response = %{
      cert_id: cert_id,
      status: :good,
      this_update: DateTime.utc_now(),
      next_update: nil
    }

    assert {:ok, der} = ResponseBuilder.build(:successful, [response], key, nonce: nonce)
    assert is_binary(der)

    {:ok, {:OCSPResponse, :successful, {:ResponseBytes, _oid, basic_der}}} =
      :OCSP.decode(:OCSPResponse, der)

    {:ok, {:BasicOCSPResponse, response_data, _alg, _sig, _certs}} =
      :OCSP.decode(:BasicOCSPResponse, basic_der)

    {:ResponseData, _v, _rid, _produced, _responses, response_extensions_der} = response_data
    refute response_extensions_der == :asn1_NOVALUE

    parsed_extensions = :public_key.der_decode(:Extensions, response_extensions_der)

    found =
      Enum.find_value(parsed_extensions, fn
        {:Extension, @nonce_oid, _critical, value} -> value
        _ -> nil
      end)

    # Compare the raw value against the DER OCTET STRING wrapping of the
    # original nonce bytes to prove the echo is byte-exact (not just present).
    expected_wrapped = <<0x04, byte_size(nonce)::8, nonce::binary>>
    assert found == expected_wrapped
  end

  test "the signature is verifiable with the cert-embedded public key", %{
    signing_key: key,
    cert_id: cert_id
  } do
    response = %{
      cert_id: cert_id,
      status: :good,
      this_update: DateTime.utc_now(),
      next_update: nil
    }

    assert {:ok, der} = ResponseBuilder.build(:successful, [response], key, nonce: nil)

    # Decode the response, extract the cert from the certs field, pull its
    # public key out, and verify the signature with THAT key. This is what a
    # real OCSP client does, and it proves the cert-key binding is correct.
    {:ok, {:OCSPResponse, :successful, {:ResponseBytes, _oid, basic_der}}} =
      :OCSP.decode(:OCSPResponse, der)

    {:ok, {:BasicOCSPResponse, response_data, _alg, signature, certs}} =
      :OCSP.decode(:BasicOCSPResponse, basic_der)

    [cert_der_from_response | _] = certs
    cert_pub = extract_ec_public_key(cert_der_from_response)

    # The TBS round-trip is byte-identical here only because OCSP.asn1 declares
    # ResponseData's sub-fields as ANY, so the codec passes them through opaquely.
    # If those fields ever became structured types, this encode/decode pair
    # could produce different bytes and the signature check below would break.
    {:ok, tbs_der} = :OCSP.encode(:ResponseData, response_data)
    tbs_bin = IO.iodata_to_binary(tbs_der)

    assert :public_key.verify(
             tbs_bin,
             :sha256,
             signature,
             {{:ECPoint, cert_pub}, {:namedCurve, @secp256r1_oid}}
           )
  end

  test "signs with ECC P-384 and the signature verifies against the cert public key", %{
    cert_id: cert_id
  } do
    {pub, priv} = :crypto.generate_key(:ecdh, :secp384r1)

    provided_key =
      {:ECPrivateKey, 1, priv, {:namedCurve, @secp384r1_oid}, pub, :asn1_NOVALUE}

    %{cert: cert_der, key: ec_priv} =
      :public_key.pkix_test_root_cert(~c"Test Responder P384", [{:key, provided_key}])

    {:ECPrivateKey, _v, priv_scalar, _curve, _pub_raw, _attrs} = ec_priv

    key = %{
      algorithm: "ecc_p384",
      signer: PkiValidation.Crypto.Signer.EcdsaP384,
      private_key: PkiValidation.Crypto.Signer.EcdsaP384.decode_private_key(priv_scalar),
      public_key: pub,
      certificate_der: cert_der
    }

    response = %{
      cert_id: cert_id,
      status: :good,
      this_update: DateTime.utc_now(),
      next_update: nil
    }

    assert {:ok, der} = ResponseBuilder.build(:successful, [response], key, nonce: nil)

    {:ok, {:OCSPResponse, :successful, {:ResponseBytes, _oid, basic_der}}} =
      :OCSP.decode(:OCSPResponse, der)

    {:ok, {:BasicOCSPResponse, response_data, _alg, signature, [cert_out | _]}} =
      :OCSP.decode(:BasicOCSPResponse, basic_der)

    cert_pub = extract_ec_public_key(cert_out)

    {:ok, tbs_der} = :OCSP.encode(:ResponseData, response_data)
    tbs_bin = IO.iodata_to_binary(tbs_der)

    assert :public_key.verify(
             tbs_bin,
             :sha384,
             signature,
             {{:ECPoint, cert_pub}, {:namedCurve, @secp384r1_oid}}
           )
  end

  test "signs with RSA-2048 and the signature verifies against the cert public key", %{
    cert_id: cert_id
  } do
    # Generate a fresh RSA-2048 keypair and mint a self-signed cert using the
    # same pkix_test_root_cert helper (passing the RSA key in via :key).
    rsa_priv_record = :public_key.generate_key({:rsa, 2048, 65537})

    %{cert: cert_der, key: _} =
      :public_key.pkix_test_root_cert(~c"Test Responder RSA", [{:key, rsa_priv_record}])

    # SigningKeyStore stores RSA private keys as DER-encoded :RSAPrivateKey
    # bytes. Mirror that shape in the test so we exercise the full sign_tbs
    # decode path (Fix D1 regression guard).
    rsa_der = :public_key.der_encode(:RSAPrivateKey, rsa_priv_record)

    key = %{
      algorithm: "rsa2048",
      signer: PkiValidation.Crypto.Signer.Rsa2048,
      private_key: PkiValidation.Crypto.Signer.Rsa2048.decode_private_key(rsa_der),
      public_key: <<>>,
      certificate_der: cert_der
    }

    response = %{
      cert_id: cert_id,
      status: :good,
      this_update: DateTime.utc_now(),
      next_update: nil
    }

    assert {:ok, der} = ResponseBuilder.build(:successful, [response], key, nonce: nil)

    {:ok, {:OCSPResponse, :successful, {:ResponseBytes, _oid, basic_der}}} =
      :OCSP.decode(:OCSPResponse, der)

    {:ok, {:BasicOCSPResponse, response_data, _alg, signature, [cert_out | _]}} =
      :OCSP.decode(:BasicOCSPResponse, basic_der)

    rsa_pub = extract_rsa_public_key(cert_out)

    {:ok, tbs_der} = :OCSP.encode(:ResponseData, response_data)
    tbs_bin = IO.iodata_to_binary(tbs_der)

    assert :public_key.verify(tbs_bin, :sha256, signature, rsa_pub)
  end

  # ---- Algorithm-dispatch path (IssuerKey / DerResponder format) ----
  # These tests exercise the second sign_tbs/2 clause added for Phase 4.
  # The signing_key uses PkiCrypto algorithm strings ("ECC-P256", "ML-DSA-65")
  # instead of the Signer.Registry format ("ecc_p256").

  describe "algorithm-dispatch path" do
    test "signs OCSP response via ECC-P256 algorithm string", %{cert_id: cert_id} do
      {pub, priv} = :crypto.generate_key(:ecdh, :secp256r1)
      ec_priv = {:ECPrivateKey, 1, priv, {:namedCurve, @secp256r1_oid}, pub, :asn1_NOVALUE}
      %{cert: cert_der} = :public_key.pkix_test_root_cert(~c"P256 Dispatch Test", [{:key, ec_priv}])

      signing_key = %{
        algorithm: "ECC-P256",
        private_key: :public_key.der_encode(:ECPrivateKey, ec_priv),
        certificate_der: cert_der
      }

      response = %{
        cert_id: cert_id,
        status: :good,
        this_update: DateTime.utc_now(),
        next_update: nil
      }

      assert {:ok, der} = ResponseBuilder.build(:successful, [response], signing_key)
      assert {:ok, {:OCSPResponse, :successful, _}} = :OCSP.decode(:OCSPResponse, der)
    end

    test "signs OCSP response via ML-DSA-65 (PQC)", %{cert_id: cert_id} do
      algo = PkiCrypto.Registry.get("ML-DSA-65")
      {:ok, %{private_key: sk}} = PkiCrypto.Algorithm.generate_keypair(algo)

      # Use a classical cert for build_responder_id — OTP cannot decode PQC certs.
      # This verifies the signing path works; cert/key pairing is not asserted here.
      {pub_ecc, priv_ecc} = :crypto.generate_key(:ecdh, :secp256r1)
      ecc_key = {:ECPrivateKey, 1, priv_ecc, {:namedCurve, @secp256r1_oid}, pub_ecc, :asn1_NOVALUE}
      %{cert: cert_der} = :public_key.pkix_test_root_cert(~c"ML-DSA-65 Responder", [{:key, ecc_key}])

      signing_key = %{
        algorithm: "ML-DSA-65",
        private_key: sk,
        certificate_der: cert_der
      }

      response = %{
        cert_id: cert_id,
        status: :good,
        this_update: DateTime.utc_now(),
        next_update: nil
      }

      assert {:ok, der} = ResponseBuilder.build(:successful, [response], signing_key)
      assert {:ok, {:OCSPResponse, :successful, _}} = :OCSP.decode(:OCSPResponse, der)
    end

    test "signs OCSP response via KAZ-SIGN-192 (PQC)", %{cert_id: cert_id} do
      algo = PkiCrypto.Registry.get("KAZ-SIGN-192")
      {:ok, %{private_key: sk}} = PkiCrypto.Algorithm.generate_keypair(algo)

      {pub_ecc, priv_ecc} = :crypto.generate_key(:ecdh, :secp256r1)
      ecc_key = {:ECPrivateKey, 1, priv_ecc, {:namedCurve, @secp256r1_oid}, pub_ecc, :asn1_NOVALUE}
      %{cert: cert_der} = :public_key.pkix_test_root_cert(~c"KAZ-SIGN-192 Responder", [{:key, ecc_key}])

      signing_key = %{
        algorithm: "KAZ-SIGN-192",
        private_key: sk,
        certificate_der: cert_der
      }

      response = %{
        cert_id: cert_id,
        status: {:revoked, DateTime.utc_now(), :keyCompromise},
        this_update: DateTime.utc_now(),
        next_update: nil
      }

      assert {:ok, der} = ResponseBuilder.build(:successful, [response], signing_key)
      assert {:ok, {:OCSPResponse, :successful, _}} = :OCSP.decode(:OCSPResponse, der)
    end
  end

  # ---- Helpers ----

  defp resolve_pub_point(:asn1_NOVALUE, cert_der) do
    plain = :public_key.pkix_decode_cert(cert_der, :plain)
    tbs = :erlang.element(2, plain)
    spki = :erlang.element(8, tbs)
    :erlang.element(3, spki)
  end

  defp resolve_pub_point(bytes, _cert_der) when is_binary(bytes), do: bytes

  defp decode_first_cert_status(der) do
    {:ok, {:OCSPResponse, :successful, {:ResponseBytes, _oid, basic_der}}} =
      :OCSP.decode(:OCSPResponse, der)

    {:ok, {:BasicOCSPResponse, response_data, _alg, _sig, _certs}} =
      :OCSP.decode(:BasicOCSPResponse, basic_der)

    {:ResponseData, _v, _rid, _produced, [single | _], _ext} = response_data
    {:SingleResponse, _cid, cert_status, _this, _next, _ext} = single
    cert_status
  end

  defp extract_ec_public_key(cert_der) do
    plain = :public_key.pkix_decode_cert(cert_der, :plain)
    tbs = :erlang.element(2, plain)
    spki = :erlang.element(8, tbs)
    :erlang.element(3, spki)
  end

  defp extract_rsa_public_key(cert_der) do
    otp = :public_key.pkix_decode_cert(cert_der, :otp)
    tbs = :erlang.element(2, otp)
    # OTPSubjectPublicKeyInfo with RSA → {:OTPSubjectPublicKeyInfo, alg, rsa_pub_record}
    spki = :erlang.element(8, tbs)
    :erlang.element(3, spki)
  end
end
