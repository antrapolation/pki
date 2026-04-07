defmodule PkiValidation.Ocsp.DerResponderTest do
  use PkiValidation.DataCase, async: false

  alias PkiValidation.Ocsp.DerResponder
  alias PkiValidation.Schema.{CertificateStatus, SigningKeyConfig}
  alias PkiValidation.{Repo, SigningKeyStore, CertId}

  setup do
    issuer_key_id = Uniq.UUID.uuid7()

    # Generate a real responder cert + key, encrypt the private key, and
    # insert a SigningKeyConfig row for the issuer.
    {_pub, priv} = :crypto.generate_key(:ecdh, :secp256r1)
    encrypted = SigningKeyStore.encrypt_for_test(priv, "test-password")
    cert_pem = generate_test_cert_pem()
    {:ok, cert_der} = decode_cert_pem(cert_pem)
    issuer_key_hash = CertId.issuer_key_hash(cert_der)

    {:ok, _} =
      %SigningKeyConfig{}
      |> SigningKeyConfig.changeset(%{
        issuer_key_id: issuer_key_id,
        algorithm: "ecc_p256",
        certificate_pem: cert_pem,
        encrypted_private_key: encrypted,
        not_before: DateTime.utc_now(),
        not_after: DateTime.add(DateTime.utc_now(), 30, :day),
        status: "active"
      })
      |> Repo.insert()

    name = :"signing_store_#{System.unique_integer([:positive])}"
    {:ok, _} = SigningKeyStore.start_link(name: name, password: "test-password")

    {:ok,
     store: name,
     issuer_key_id: issuer_key_id,
     issuer_key_hash: issuer_key_hash}
  end

  test "responds with :successful for an active certificate", ctx do
    serial_int = 100

    {:ok, _} =
      %CertificateStatus{}
      |> CertificateStatus.changeset(%{
        serial_number: Integer.to_string(serial_int),
        issuer_key_id: ctx.issuer_key_id,
        subject_dn: "CN=Active",
        status: "active",
        not_before: DateTime.utc_now(),
        not_after: DateTime.add(DateTime.utc_now(), 1, :day)
      })
      |> Repo.insert()

    request = build_request(ctx.issuer_key_hash, serial_int)

    assert {:ok, der} = DerResponder.respond(request, signing_key_store: ctx.store)
    {:ok, {:OCSPResponse, status, _bytes}} = :OCSP.decode(:OCSPResponse, der)
    assert status == :successful
  end

  test "responds with :successful and revoked status for a revoked certificate", ctx do
    serial_int = 200
    serial = Integer.to_string(serial_int)

    {:ok, _} =
      %CertificateStatus{}
      |> CertificateStatus.changeset(%{
        serial_number: serial,
        issuer_key_id: ctx.issuer_key_id,
        subject_dn: "CN=Revoked",
        status: "revoked",
        not_before: DateTime.utc_now(),
        not_after: DateTime.add(DateTime.utc_now(), 1, :day),
        revoked_at: DateTime.utc_now(),
        revocation_reason: "key_compromise"
      })
      |> Repo.insert()

    request = build_request(ctx.issuer_key_hash, serial_int)

    assert {:ok, der} = DerResponder.respond(request, signing_key_store: ctx.store)
    {:ok, {:OCSPResponse, status, _bytes}} = :OCSP.decode(:OCSPResponse, der)
    assert status == :successful

    {:ok, {:OCSPResponse, :successful, {:ResponseBytes, _oid, basic_der}}} =
      :OCSP.decode(:OCSPResponse, der)

    {:ok, {:BasicOCSPResponse, response_data, _alg, _sig, _certs}} =
      :OCSP.decode(:BasicOCSPResponse, basic_der)

    {:ResponseData, _v, _rid, _produced, [single_response | _], _ext} = response_data
    {:SingleResponse, _cid, cert_status, _this, _next, _ext} = single_response
    assert match?({:revoked, _}, cert_status)
  end

  test "responds with :successful and unknown status when serial is missing", ctx do
    request = build_request(ctx.issuer_key_hash, 999)

    assert {:ok, der} = DerResponder.respond(request, signing_key_store: ctx.store)

    {:ok, {:OCSPResponse, :successful, {:ResponseBytes, _oid, basic_der}}} =
      :OCSP.decode(:OCSPResponse, der)

    {:ok, {:BasicOCSPResponse, response_data, _alg, _sig, _certs}} =
      :OCSP.decode(:BasicOCSPResponse, basic_der)

    {:ResponseData, _v, _rid, _produced, [single_response | _], _ext} = response_data
    {:SingleResponse, _cid, cert_status, _this, _next, _ext} = single_response
    assert match?({:unknown, _}, cert_status)
  end

  test "responds with :unauthorized when issuer_key_hash matches no signing key", ctx do
    unknown_hash = :crypto.strong_rand_bytes(20)
    request = build_request(unknown_hash, 100)

    assert {:ok, der} = DerResponder.respond(request, signing_key_store: ctx.store)
    {:ok, {:OCSPResponse, status, body}} = :OCSP.decode(:OCSPResponse, der)
    assert status == :unauthorized
    assert body == :asn1_NOVALUE
  end

  test "echoes the request nonce in the response", ctx do
    serial_int = 300
    serial = Integer.to_string(serial_int)
    nonce = :crypto.strong_rand_bytes(16)

    {:ok, _} =
      %CertificateStatus{}
      |> CertificateStatus.changeset(%{
        serial_number: serial,
        issuer_key_id: ctx.issuer_key_id,
        subject_dn: "CN=Nonce",
        status: "active",
        not_before: DateTime.utc_now(),
        not_after: DateTime.add(DateTime.utc_now(), 1, :day)
      })
      |> Repo.insert()

    request = %{
      cert_ids: [
        %{
          issuer_name_hash: :crypto.strong_rand_bytes(20),
          issuer_key_hash: ctx.issuer_key_hash,
          serial_number: serial_int
        }
      ],
      nonce: nonce
    }

    assert {:ok, der} = DerResponder.respond(request, signing_key_store: ctx.store)

    {:ok, {:OCSPResponse, :successful, {:ResponseBytes, _oid, basic_der}}} =
      :OCSP.decode(:OCSPResponse, der)

    {:ok, {:BasicOCSPResponse, response_data, _alg, _sig, _certs}} =
      :OCSP.decode(:BasicOCSPResponse, basic_der)

    {:ResponseData, _v, _rid, _produced, _resps, response_extensions_der} = response_data
    refute response_extensions_der == :asn1_NOVALUE

    parsed = :public_key.der_decode(:Extensions, response_extensions_der)
    nonce_oid = {1, 3, 6, 1, 5, 5, 7, 48, 1, 2}

    found =
      Enum.find_value(parsed, fn
        {:Extension, ^nonce_oid, _critical, value} -> value
        _ -> nil
      end)

    refute is_nil(found), "nonce extension should be present in response"
  end

  # ---- Helpers ----

  defp build_request(issuer_key_hash, serial) do
    %{
      cert_ids: [
        %{
          issuer_name_hash: :crypto.strong_rand_bytes(20),
          issuer_key_hash: issuer_key_hash,
          serial_number: serial
        }
      ],
      nonce: nil
    }
  end

  defp generate_test_cert_pem do
    case :public_key.pkix_test_root_cert(~c"Test Responder", []) do
      %{cert: der} when is_binary(der) ->
        :public_key.pem_encode([{:Certificate, der, :not_encrypted}])

      {tbs, _key} ->
        der = :public_key.pkix_encode(:OTPCertificate, tbs, :otp)
        :public_key.pem_encode([{:Certificate, der, :not_encrypted}])
    end
  end

  defp decode_cert_pem(pem) do
    case :public_key.pem_decode(pem) do
      [{:Certificate, der, _} | _] -> {:ok, der}
      _ -> {:error, :invalid_cert_pem}
    end
  end
end
