defmodule PkiValidation.Ocsp.ResponseBuilderTest do
  use ExUnit.Case, async: true

  alias PkiValidation.Ocsp.ResponseBuilder

  setup do
    {pub, priv} = :crypto.generate_key(:ecdh, :secp256r1)

    cert_der =
      case :public_key.pkix_test_root_cert(~c"Test Responder", []) do
        %{cert: der} when is_binary(der) -> der
        {tbs, _key} -> :public_key.pkix_encode(:OTPCertificate, tbs, :otp)
      end

    signing_key = %{
      algorithm: "ecc_p256",
      private_key: priv,
      public_key: pub,
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

  test "echoes nonce when provided", %{signing_key: key, cert_id: cert_id} do
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
    nonce_oid = {1, 3, 6, 1, 5, 5, 7, 48, 1, 2}

    assert Enum.find(parsed_extensions, fn
             {:Extension, ^nonce_oid, _, _} -> true
             _ -> false
           end)
  end

  test "the signature is verifiable with the responder public key", %{
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

    {:ok, {:OCSPResponse, :successful, {:ResponseBytes, _oid, basic_der}}} =
      :OCSP.decode(:OCSPResponse, der)

    {:ok, {:BasicOCSPResponse, response_data, _alg, signature, _certs}} =
      :OCSP.decode(:BasicOCSPResponse, basic_der)

    {:ok, tbs_der} = :OCSP.encode(:ResponseData, response_data)
    tbs_bin = IO.iodata_to_binary(tbs_der)

    pub_point = key.public_key

    assert :public_key.verify(
             tbs_bin,
             :sha256,
             signature,
             {{:ECPoint, pub_point}, {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}}}
           )
  end
end
