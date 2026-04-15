defmodule PkiCrypto.Integration.PqcIssuerTest do
  use ExUnit.Case, async: true

  alias PkiCrypto.{Csr, X509Builder}

  describe "PQC issuer matrix" do
    test "KAZ-SIGN-192 root → ECDSA-P256 sub-CA verifies" do
      {root_cert_der, root_priv, root_pub, root_algo} =
        build_pqc_root("KAZ-SIGN-192", "/CN=KAZ Root")

      sub_priv = X509.PrivateKey.new_ec(:secp256r1)
      {:ok, csr_pem} = Csr.generate("ECC-P256", sub_priv, "/CN=ECDSA Sub")
      {:ok, csr} = Csr.parse(csr_pem)
      assert :ok = Csr.verify_pop(csr)

      {:ok, tbs, _} =
        X509Builder.build_tbs_cert(
          csr,
          %{cert_der: root_cert_der, algorithm_id: "KAZ-SIGN-192"},
          "/CN=ECDSA Sub",
          365,
          7001
        )

      {:ok, cert_der} = X509Builder.sign_tbs(tbs, "KAZ-SIGN-192", root_priv)

      {outer, <<>>} = PkiCrypto.Asn1.read_sequence(cert_der)
      [_tbs_back, _sig_alg, sig_bits] = PkiCrypto.Asn1.read_sequence_items(outer)
      {signature, <<>>} = PkiCrypto.Asn1.read_bit_string(sig_bits)

      assert :ok = PkiCrypto.Algorithm.verify(root_algo, root_pub, signature, tbs)
    end

    test "ML-DSA-65 root → KAZ-SIGN-128 leaf (cross-family PQC)" do
      {root_cert_der, root_priv, root_pub, root_algo} =
        build_pqc_root("ML-DSA-65", "/CN=ML-DSA Root")

      leaf_algo = PkiCrypto.Registry.get("KAZ-SIGN-128")

      {:ok, %{public_key: leaf_pub, private_key: leaf_priv}} =
        PkiCrypto.Algorithm.generate_keypair(leaf_algo)

      {:ok, csr_pem} =
        Csr.generate(
          "KAZ-SIGN-128",
          %{public_key: leaf_pub, private_key: leaf_priv},
          "/CN=KAZ Leaf"
        )

      {:ok, csr} = Csr.parse(csr_pem)
      assert :ok = Csr.verify_pop(csr)

      {:ok, tbs, _} =
        X509Builder.build_tbs_cert(
          csr,
          %{cert_der: root_cert_der, algorithm_id: "ML-DSA-65"},
          "/CN=KAZ Leaf",
          365,
          7002
        )

      {:ok, cert_der} = X509Builder.sign_tbs(tbs, "ML-DSA-65", root_priv)

      {outer, <<>>} = PkiCrypto.Asn1.read_sequence(cert_der)
      [_tbs_back, _sig_alg, sig_bits] = PkiCrypto.Asn1.read_sequence_items(outer)
      {signature, <<>>} = PkiCrypto.Asn1.read_bit_string(sig_bits)

      assert :ok = PkiCrypto.Algorithm.verify(root_algo, root_pub, signature, tbs)
    end

    test "KAZ-SIGN-256 root → KAZ-SIGN-128 leaf (same-family PQC, different levels)" do
      {root_cert_der, root_priv, root_pub, root_algo} =
        build_pqc_root("KAZ-SIGN-256", "/CN=KAZ-256 Root")

      leaf_algo = PkiCrypto.Registry.get("KAZ-SIGN-128")

      {:ok, %{public_key: leaf_pub, private_key: leaf_priv}} =
        PkiCrypto.Algorithm.generate_keypair(leaf_algo)

      {:ok, csr_pem} =
        Csr.generate(
          "KAZ-SIGN-128",
          %{public_key: leaf_pub, private_key: leaf_priv},
          "/CN=KAZ-128 Leaf"
        )

      {:ok, csr} = Csr.parse(csr_pem)
      {:ok, tbs, _} =
        X509Builder.build_tbs_cert(
          csr,
          %{cert_der: root_cert_der, algorithm_id: "KAZ-SIGN-256"},
          "/CN=KAZ-128 Leaf",
          365,
          7003
        )

      {:ok, cert_der} = X509Builder.sign_tbs(tbs, "KAZ-SIGN-256", root_priv)

      {outer, <<>>} = PkiCrypto.Asn1.read_sequence(cert_der)
      [_tbs_back, _sig_alg, sig_bits] = PkiCrypto.Asn1.read_sequence_items(outer)
      {signature, <<>>} = PkiCrypto.Asn1.read_bit_string(sig_bits)

      assert :ok = PkiCrypto.Algorithm.verify(root_algo, root_pub, signature, tbs)
    end
  end

  # --- Helpers ---

  defp build_pqc_root(algorithm_id, subject_dn) do
    algo = PkiCrypto.Registry.get(algorithm_id)
    {:ok, %{public_key: pub, private_key: priv}} = PkiCrypto.Algorithm.generate_keypair(algo)

    {:ok, cert_der} =
      X509Builder.self_sign(algorithm_id, %{public_key: pub, private_key: priv}, subject_dn, 3650)

    {cert_der, priv, pub, algo}
  end
end
