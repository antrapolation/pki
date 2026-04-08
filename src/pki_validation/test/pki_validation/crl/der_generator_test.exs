defmodule PkiValidation.Crl.DerGeneratorTest do
  use PkiValidation.DataCase, async: false

  alias PkiValidation.Crl.DerGenerator
  alias PkiValidation.Schema.{CertificateStatus, CrlMetadata}
  alias PkiValidation.Repo

  setup do
    issuer_key_id = Uniq.UUID.uuid7()

    # Generate a P-256 key + cert pair where the cert is actually signed
    # with that key. This matches the I-1 lesson from Phase 3.5: the cert
    # in the response certs field must correspond to the signing key.
    {pub_point, priv_scalar} = :crypto.generate_key(:ecdh, :secp256r1)
    p256_oid = {1, 2, 840, 10045, 3, 1, 7}

    ec_priv_record =
      {:ECPrivateKey, 1, priv_scalar, {:namedCurve, p256_oid}, pub_point, :asn1_NOVALUE}

    %{cert: cert_der} =
      :public_key.pkix_test_root_cert(~c"Test CRL Signer", [{:key, ec_priv_record}])

    signing_key = %{
      algorithm: "ecc_p256",
      signer: PkiValidation.Crypto.Signer.EcdsaP256,
      private_key: PkiValidation.Crypto.Signer.EcdsaP256.decode_private_key(priv_scalar),
      public_key: pub_point,
      certificate_der: cert_der
    }

    {:ok, issuer_key_id: issuer_key_id, signing_key: signing_key, p256_oid: p256_oid}
  end

  test "generates a DER CRL with one revoked entry", ctx do
    insert_revoked_cert(ctx.issuer_key_id, "100", "key_compromise")

    assert {:ok, der, crl_number} = DerGenerator.generate(ctx.issuer_key_id, ctx.signing_key)
    assert is_binary(der)
    assert crl_number == 1

    # Decode via :public_key and assert the structure is a valid CertificateList
    cert_list = :public_key.der_decode(:CertificateList, der)
    assert {:CertificateList, _tbs, _alg, _signature} = cert_list
  end

  test "generated CRL contains the revoked serial with the correct reason", ctx do
    insert_revoked_cert(ctx.issuer_key_id, "200", "key_compromise")

    {:ok, der, _} = DerGenerator.generate(ctx.issuer_key_id, ctx.signing_key)
    {:CertificateList, tbs, _alg, _sig} = :public_key.der_decode(:CertificateList, der)

    revoked = extract_revoked(tbs)
    assert length(revoked) == 1
    [{_, serial_int, _time, extensions} | _] = revoked
    assert serial_int == 200

    # The reason extension is in the extensions list
    reason_ext = Enum.find(extensions, fn {:Extension, oid, _, _} -> oid == {2, 5, 29, 21} end)
    refute is_nil(reason_ext)
  end

  test "generates an empty CRL when there are no revoked certs", ctx do
    assert {:ok, der, _} = DerGenerator.generate(ctx.issuer_key_id, ctx.signing_key)
    {:CertificateList, tbs, _alg, _sig} = :public_key.der_decode(:CertificateList, der)

    case extract_revoked(tbs) do
      :asn1_NOVALUE -> :ok
      [] -> :ok
      list when is_list(list) -> assert list == []
    end
  end

  test "increments crl_number monotonically across calls", ctx do
    {:ok, _der1, n1} = DerGenerator.generate(ctx.issuer_key_id, ctx.signing_key)
    {:ok, _der2, n2} = DerGenerator.generate(ctx.issuer_key_id, ctx.signing_key)
    {:ok, _der3, n3} = DerGenerator.generate(ctx.issuer_key_id, ctx.signing_key)

    assert n1 == 1
    assert n2 == 2
    assert n3 == 3
  end

  test "persists signed DER bytes and metadata in crl_metadata", ctx do
    insert_revoked_cert(ctx.issuer_key_id, "300", "superseded")

    {:ok, der, n} = DerGenerator.generate(ctx.issuer_key_id, ctx.signing_key)

    meta = Repo.get_by(CrlMetadata, issuer_key_id: ctx.issuer_key_id)
    refute is_nil(meta)
    assert meta.last_der_bytes == der
    assert meta.last_der_size == byte_size(der)
    assert meta.generation_count >= 1
    refute is_nil(meta.last_generated_at)
    # The stored crl_number is the NEXT one to issue, i.e. n + 1
    assert meta.crl_number == n + 1
  end

  test "the CRL signature is verifiable with the cert-extracted public key", ctx do
    insert_revoked_cert(ctx.issuer_key_id, "400", "key_compromise")

    {:ok, der, _} = DerGenerator.generate(ctx.issuer_key_id, ctx.signing_key)

    {:CertificateList, tbs, _alg, signature} = :public_key.der_decode(:CertificateList, der)
    tbs_der = :public_key.der_encode(:TBSCertList, tbs)

    # Extract the public key from the SAME cert that signed the CRL.
    # This proves the cert-key binding.
    plain = :public_key.pkix_decode_cert(ctx.signing_key.certificate_der, :plain)
    cert_tbs = :erlang.element(2, plain)
    spki = :erlang.element(8, cert_tbs)
    cert_pub = :erlang.element(3, spki)

    assert :public_key.verify(
             tbs_der,
             :sha256,
             signature,
             {{:ECPoint, cert_pub}, {:namedCurve, ctx.p256_oid}}
           )
  end

  test "scopes revoked entries by issuer_key_id", ctx do
    other_issuer = Uniq.UUID.uuid7()
    insert_revoked_cert(ctx.issuer_key_id, "500", "key_compromise")
    insert_revoked_cert(other_issuer, "600", "key_compromise")

    {:ok, der, _} = DerGenerator.generate(ctx.issuer_key_id, ctx.signing_key)
    {:CertificateList, tbs, _, _} = :public_key.der_decode(:CertificateList, der)

    revoked = extract_revoked(tbs)
    serials = Enum.map(revoked, fn {_, s, _, _} -> s end)
    assert 500 in serials
    refute 600 in serials
  end

  test "tolerates out-of-band rows with unknown revocation_reason", ctx do
    # Bypass the changeset enum validation to simulate a row inserted
    # directly via SQL / migration / manual ops with a reason that isn't
    # in the known set. Without the defensive catch-all in reason_to_atom,
    # this would raise FunctionClauseError and take down CRL generation
    # for the entire issuer.
    {:ok, _} =
      Ecto.Adapters.SQL.query(
        Repo,
        """
        INSERT INTO certificate_status
          (id, serial_number, issuer_key_id, subject_dn, status,
           not_before, not_after, revoked_at, revocation_reason,
           inserted_at, updated_at)
        VALUES
          ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        """,
        [
          Uniq.UUID.uuid7(:raw),
          "700",
          Uniq.UUID.string_to_binary!(ctx.issuer_key_id),
          "CN=OutOfBand",
          "revoked",
          DateTime.utc_now(),
          DateTime.add(DateTime.utc_now(), 1, :day),
          DateTime.utc_now(),
          "exotic_reason_not_in_enum",
          DateTime.utc_now(),
          DateTime.utc_now()
        ]
      )

    assert {:ok, der, _} = DerGenerator.generate(ctx.issuer_key_id, ctx.signing_key)
    {:CertificateList, tbs, _, _} = :public_key.der_decode(:CertificateList, der)
    revoked = extract_revoked(tbs)

    # The entry should still appear in the CRL; the reason just falls
    # back to :unspecified which is a valid CRLReason.
    serials = Enum.map(revoked, fn {_, s, _, _} -> s end)
    assert 700 in serials
  end

  # ---- Helpers ----

  defp insert_revoked_cert(issuer_key_id, serial, reason) do
    {:ok, _} =
      %CertificateStatus{}
      |> CertificateStatus.changeset(%{
        serial_number: serial,
        issuer_key_id: issuer_key_id,
        subject_dn: "CN=Cert#{serial}",
        status: "revoked",
        not_before: DateTime.utc_now(),
        not_after: DateTime.add(DateTime.utc_now(), 1, :day),
        revoked_at: DateTime.utc_now(),
        revocation_reason: reason
      })
      |> Repo.insert()
  end

  defp extract_revoked(tbs) do
    # TBSCertList shape (OTP 27):
    #   {:TBSCertList, version, signature_alg, issuer, this_update, next_update,
    #    revoked_certificates, crl_extensions}
    # revokedCertificates is at element 7 (1-indexed).
    case :erlang.element(7, tbs) do
      :asn1_NOVALUE -> []
      list when is_list(list) -> list
    end
  end
end
