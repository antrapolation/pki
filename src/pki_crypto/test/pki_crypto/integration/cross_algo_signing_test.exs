defmodule PkiCrypto.Integration.CrossAlgoSigningTest do
  use ExUnit.Case, async: true

  alias PkiCrypto.{Csr, X509Builder}

  describe "ECDSA-P384 root issuing a KAZ-SIGN-192 sub-CA" do
    test "full flow: CSR → root signs → cert parses → signature verifies" do
      # 1. Build an ECDSA-P384 root CA
      root_priv = X509.PrivateKey.new_ec(:secp384r1)
      root_cert = X509.Certificate.self_signed(root_priv, "/CN=ECDSA Root CA")

      # 2. Generate a KAZ-SIGN-192 sub-CA keypair
      algo = PkiCrypto.Registry.get("KAZ-SIGN-192")
      {:ok, %{public_key: sub_pub, private_key: sub_priv}} =
        PkiCrypto.Algorithm.generate_keypair(algo)

      # 3. Sub-CA builds a PKCS#10 CSR, self-signed with KAZ-SIGN-192
      {:ok, csr_pem} =
        Csr.generate(
          "KAZ-SIGN-192",
          %{public_key: sub_pub, private_key: sub_priv},
          "/CN=KAZ-SIGN Sub CA"
        )

      # 4. Parse + verify the CSR's PoP
      {:ok, parsed} = Csr.parse(csr_pem)
      assert :ok = Csr.verify_pop(parsed)
      assert parsed.algorithm_id == "KAZ-SIGN-192"

      # 5. Root builds a TBS cert and signs with ECDSA-P384
      {:ok, tbs, sig_oid} =
        X509Builder.build_tbs_cert(
          parsed,
          %{
            cert_der: X509.Certificate.to_der(root_cert),
            algorithm_id: "ECC-P384"
          },
          "/CN=KAZ-SIGN Sub CA",
          1825,
          1001
        )

      assert sig_oid == {1, 2, 840, 10045, 4, 3, 3}

      {:ok, cert_der} = X509Builder.sign_tbs(tbs, "ECC-P384", root_priv)

      # 6. Structurally parse the emitted cert
      {outer, <<>>} = PkiCrypto.Asn1.read_sequence(cert_der)
      [tbs_back, sig_alg, sig_bits] = PkiCrypto.Asn1.read_sequence_items(outer)
      assert tbs_back == tbs

      {alg_body, <<>>} = PkiCrypto.Asn1.read_sequence(sig_alg)
      [alg_oid_der] = PkiCrypto.Asn1.read_sequence_items(alg_body)
      {oid, <<>>} = PkiCrypto.Asn1.read_oid(alg_oid_der)
      assert oid == {1, 2, 840, 10045, 4, 3, 3}

      {signature, <<>>} = PkiCrypto.Asn1.read_bit_string(sig_bits)
      assert is_binary(signature) and byte_size(signature) > 0

      # 7. Verify the root's signature over TBS using :public_key
      pub_from_cert = X509.Certificate.public_key(root_cert)
      assert :public_key.verify(tbs, :sha384, signature, pub_from_cert)

      # 8. Subject key embedded in cert
      assert :binary.match(cert_der, sub_pub) != :nomatch
    end
  end

  describe "regression — ECDSA root issuing an ECDSA-P256 leaf (classical→classical)" do
    test "the new orchestrator still emits a valid classical-signed cert" do
      root_priv = X509.PrivateKey.new_ec(:secp384r1)
      root_cert = X509.Certificate.self_signed(root_priv, "/CN=Root")

      leaf_priv = X509.PrivateKey.new_ec(:secp256r1)
      {:ok, csr_pem} = Csr.generate("ECC-P256", leaf_priv, "/CN=Leaf")
      {:ok, parsed} = Csr.parse(csr_pem)
      assert :ok = Csr.verify_pop(parsed)

      {:ok, tbs, _} =
        X509Builder.build_tbs_cert(
          parsed,
          %{
            cert_der: X509.Certificate.to_der(root_cert),
            algorithm_id: "ECC-P384"
          },
          "/CN=Leaf",
          365,
          2001
        )

      {:ok, cert_der} = X509Builder.sign_tbs(tbs, "ECC-P384", root_priv)

      {outer, <<>>} = PkiCrypto.Asn1.read_sequence(cert_der)
      [tbs_back, _sig_alg, sig_bits] = PkiCrypto.Asn1.read_sequence_items(outer)
      {signature, <<>>} = PkiCrypto.Asn1.read_bit_string(sig_bits)

      pub_from_cert = X509.Certificate.public_key(root_cert)
      assert :public_key.verify(tbs_back, :sha384, signature, pub_from_cert)
    end
  end
end
