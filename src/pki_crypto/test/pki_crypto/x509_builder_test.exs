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
end
