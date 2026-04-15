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

    test "PQC issuer returns :pqc_issuer_not_yet_supported" do
      # fabricate a fake TBS — we only exercise the dispatch path
      assert {:error, {:pqc_issuer_not_yet_supported, :kaz_sign}} =
               X509Builder.sign_tbs(<<0x30, 0x00>>, "KAZ-SIGN-192", <<1, 2, 3>>)
    end

    test "unknown issuer algorithm returns error" do
      assert {:error, :unknown_issuer_algorithm} = X509Builder.sign_tbs(<<0x30, 0x00>>, "NOT-REAL", <<>>)
    end
  end
end
