defmodule PkiCrypto.X509BuilderTest do
  use ExUnit.Case, async: true

  alias PkiCrypto.{Csr, X509Builder}

  describe "build_tbs_cert/5 — classical issuer, PQC subject" do
    setup do
      issuer_priv = X509.PrivateKey.new_ec(:secp384r1)
      issuer_cert = X509.Certificate.self_signed(issuer_priv, "/CN=Root")

      algo = PkiCrypto.Registry.get("KAZ-SIGN-192")
      {:ok, %{public_key: pub, private_key: priv}} = PkiCrypto.Algorithm.generate_keypair(algo)
      {:ok, csr_pem} = Csr.generate("KAZ-SIGN-192", %{public_key: pub, private_key: priv}, "/CN=Sub CA")
      {:ok, csr} = Csr.parse(csr_pem)

      %{issuer_priv: issuer_priv, issuer_cert: issuer_cert, csr: csr, subject_pub: pub}
    end

    test "produces DER whose outer structure is SEQUENCE", ctx do
      {:ok, tbs_der, _sig_alg_oid} =
        X509Builder.build_tbs_cert(
          ctx.csr,
          %{
            cert_der: X509.Certificate.to_der(ctx.issuer_cert),
            algorithm_id: "ECC-P384"
          },
          "/CN=Sub CA",
          365,
          12345
        )

      assert <<0x30, _rest::binary>> = tbs_der
    end

    test "signature_algorithm_oid is the ISSUER's OID", ctx do
      {:ok, _tbs, sig_alg_oid} =
        X509Builder.build_tbs_cert(
          ctx.csr,
          %{
            cert_der: X509.Certificate.to_der(ctx.issuer_cert),
            algorithm_id: "ECC-P384"
          },
          "/CN=Sub CA",
          365,
          12345
        )

      assert sig_alg_oid == {1, 2, 840, 10045, 4, 3, 3}
    end

    test "embeds subject's PQC public key in SPKI", ctx do
      {:ok, tbs_der, _} =
        X509Builder.build_tbs_cert(
          ctx.csr,
          %{
            cert_der: X509.Certificate.to_der(ctx.issuer_cert),
            algorithm_id: "ECC-P384"
          },
          "/CN=Sub CA",
          365,
          12345
        )

      assert :binary.match(tbs_der, ctx.subject_pub) != :nomatch
    end
  end

  describe "sign_tbs/3 — classical issuer" do
    test "ECDSA-P384 signs a TBS and the resulting cert structurally parses" do
      issuer_priv = X509.PrivateKey.new_ec(:secp384r1)
      issuer_cert = X509.Certificate.self_signed(issuer_priv, "/CN=Root")

      algo = PkiCrypto.Registry.get("KAZ-SIGN-192")
      {:ok, %{public_key: pub, private_key: priv}} = PkiCrypto.Algorithm.generate_keypair(algo)
      {:ok, csr_pem} = PkiCrypto.Csr.generate("KAZ-SIGN-192", %{public_key: pub, private_key: priv}, "/CN=Sub CA")
      {:ok, csr} = PkiCrypto.Csr.parse(csr_pem)

      {:ok, tbs, _} =
        X509Builder.build_tbs_cert(
          csr,
          %{cert_der: X509.Certificate.to_der(issuer_cert), algorithm_id: "ECC-P384"},
          "/CN=Sub CA",
          365,
          12345
        )

      {:ok, cert_der} = X509Builder.sign_tbs(tbs, "ECC-P384", issuer_priv)

      assert <<0x30, _::binary>> = cert_der

      {outer_body, <<>>} = PkiCrypto.Asn1.read_sequence(cert_der)
      [tbs_back, sig_alg, sig_bit_string] = PkiCrypto.Asn1.read_sequence_items(outer_body)

      assert tbs_back == tbs
      assert <<0x30, _::binary>> = sig_alg
      assert <<0x03, _::binary>> = sig_bit_string
    end

    test "unknown issuer algorithm returns error" do
      assert {:error, :unknown_issuer_algorithm} = X509Builder.sign_tbs(<<0x30, 0x00>>, "NOT-REAL", <<>>)
    end
  end

  describe "sign_tbs/3 — PQC issuer" do
    test "KAZ-SIGN-192 root signs ECDSA sub-CA CSR; signature verifies via PkiCrypto.Algorithm" do
      # PQC root keypair
      algo = PkiCrypto.Registry.get("KAZ-SIGN-192")
      {:ok, %{public_key: root_pub, private_key: root_priv}} = PkiCrypto.Algorithm.generate_keypair(algo)

      # Classical subject CSR
      sub_priv = X509.PrivateKey.new_ec(:secp256r1)
      {:ok, csr_pem} = PkiCrypto.Csr.generate("ECC-P256", sub_priv, "/CN=ECDSA Sub")
      {:ok, csr} = PkiCrypto.Csr.parse(csr_pem)

      # Build a stub root cert for AKI extension — real X.509 with PQC SPKI,
      # constructed directly via Asn1 primitives (self-sign/4 comes in Task 3).
      root_cert_der = build_stub_pqc_root_cert("KAZ-SIGN-192", root_pub, root_priv, "/CN=KAZ Root", algo)

      # Root signs sub-CA CSR with KAZ-SIGN-192
      {:ok, tbs, _} =
        PkiCrypto.X509Builder.build_tbs_cert(
          csr,
          %{cert_der: root_cert_der, algorithm_id: "KAZ-SIGN-192"},
          "/CN=ECDSA Sub",
          365,
          5001
        )

      {:ok, cert_der} = PkiCrypto.X509Builder.sign_tbs(tbs, "KAZ-SIGN-192", root_priv)

      {outer, <<>>} = PkiCrypto.Asn1.read_sequence(cert_der)
      [tbs_back, sig_alg, sig_bits] = PkiCrypto.Asn1.read_sequence_items(outer)
      assert tbs_back == tbs

      {alg_body, <<>>} = PkiCrypto.Asn1.read_sequence(sig_alg)
      [alg_oid_der] = PkiCrypto.Asn1.read_sequence_items(alg_body)
      {oid, <<>>} = PkiCrypto.Asn1.read_oid(alg_oid_der)
      assert oid == {1, 3, 6, 1, 4, 1, 99999, 1, 1, 2}

      {signature, <<>>} = PkiCrypto.Asn1.read_bit_string(sig_bits)
      assert :ok = PkiCrypto.Algorithm.verify(algo, root_pub, signature, tbs)
    end
  end

  # --- Test helpers ---

  # Build a minimal X.509 root cert with a PQC SubjectPublicKeyInfo, self-signed
  # via PkiCrypto.Algorithm.sign. Used only as an "issuer cert" for AKI extension
  # extraction until X509Builder.self_sign/4 (Task 3) replaces it.
  defp build_stub_pqc_root_cert(algorithm_id, pub, priv, subject_dn, algo) do
    {:ok, %{sig_alg_oid: sig_oid, public_key_oid: pk_oid}} =
      PkiCrypto.AlgorithmRegistry.by_id(algorithm_id)

    version = PkiCrypto.Asn1.tagged(0, :explicit, PkiCrypto.Asn1.integer(2))
    serial = PkiCrypto.Asn1.integer(1)
    sig_alg = PkiCrypto.Asn1.sequence([PkiCrypto.Asn1.oid(sig_oid)])
    name = stub_encode_name(subject_dn)

    now = DateTime.utc_now() |> DateTime.truncate(:second)
    not_after = DateTime.add(now, 365 * 86_400, :second)
    validity = PkiCrypto.Asn1.sequence([PkiCrypto.Asn1.utc_time(now), PkiCrypto.Asn1.utc_time(not_after)])

    spki =
      PkiCrypto.Asn1.sequence([
        PkiCrypto.Asn1.sequence([PkiCrypto.Asn1.oid(pk_oid)]),
        PkiCrypto.Asn1.bit_string(pub)
      ])

    tbs = PkiCrypto.Asn1.sequence([version, serial, sig_alg, name, validity, name, spki])
    {:ok, sig} = PkiCrypto.Algorithm.sign(algo, priv, tbs)
    PkiCrypto.Asn1.sequence([tbs, sig_alg, PkiCrypto.Asn1.bit_string(sig)])
  end

  defp stub_encode_name(dn_string) do
    parts =
      dn_string
      |> String.split("/", trim: true)
      |> Enum.map(fn part ->
        [k, v] = String.split(part, "=", parts: 2)
        {stub_dn_oid(k), v}
      end)

    rdns =
      Enum.map(parts, fn {oid, value} ->
        atv =
          PkiCrypto.Asn1.sequence([
            PkiCrypto.Asn1.oid(oid),
            <<0x0C, byte_size(value)>> <> value
          ])

        PkiCrypto.Asn1.set([atv])
      end)

    PkiCrypto.Asn1.sequence(rdns)
  end

  defp stub_dn_oid("CN"), do: {2, 5, 4, 3}
end
