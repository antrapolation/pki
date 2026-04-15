defmodule PkiCrypto.CsrTest do
  use ExUnit.Case, async: true

  alias PkiCrypto.Csr

  describe "parse/1 on a classical ECDSA-P256 CSR" do
    setup do
      private_key = X509.PrivateKey.new_ec(:secp256r1)
      csr = X509.CSR.new(private_key, "/CN=Test Subject/O=Acme")
      pem = X509.CSR.to_pem(csr)

      %{pem: pem, private_key: private_key}
    end

    test "extracts subject DN, algorithm, public key, raw TBS, and signature", %{pem: pem} do
      assert {:ok, parsed} = Csr.parse(pem)

      assert parsed.algorithm_id == "ECC-P256"
      assert parsed.subject_dn =~ "CN=Test Subject"
      assert is_binary(parsed.subject_public_key)
      assert byte_size(parsed.subject_public_key) > 0
      assert is_binary(parsed.raw_tbs)
      assert is_binary(parsed.signature)
    end

    test "raw_tbs starts with SEQUENCE tag (DER of CertificationRequestInfo)", %{pem: pem} do
      {:ok, parsed} = Csr.parse(pem)
      assert byte_size(parsed.raw_tbs) > 0
      assert <<0x30, _rest::binary>> = parsed.raw_tbs
    end
  end

  describe "parse/1 error paths" do
    test "returns error on non-PEM garbage" do
      assert {:error, _} = Csr.parse("not a pem")
    end

    test "returns error on unknown algorithm OID" do
      bogus_oid = PkiCrypto.Asn1.oid({1, 2, 3, 4, 5})
      bogus_alg_id = PkiCrypto.Asn1.sequence([bogus_oid])
      bogus_spki = PkiCrypto.Asn1.sequence([bogus_alg_id, PkiCrypto.Asn1.bit_string(<<0, 0, 0>>)])
      bogus_name = PkiCrypto.Asn1.sequence([])
      bogus_attrs = PkiCrypto.Asn1.tagged(0, :explicit, <<>>)

      bogus_tbs =
        PkiCrypto.Asn1.sequence([
          PkiCrypto.Asn1.integer(0),
          bogus_name,
          bogus_spki,
          bogus_attrs
        ])

      bogus_sig_alg = PkiCrypto.Asn1.sequence([bogus_oid])

      bogus_csr_der =
        PkiCrypto.Asn1.sequence([
          bogus_tbs,
          bogus_sig_alg,
          PkiCrypto.Asn1.bit_string(<<0, 0, 0>>)
        ])

      pem =
        "-----BEGIN CERTIFICATE REQUEST-----\n" <>
          Base.encode64(bogus_csr_der) <>
          "\n-----END CERTIFICATE REQUEST-----\n"

      assert {:error, :unknown_algorithm_oid} = Csr.parse(pem)
    end
  end

  describe "generate/3 for classical" do
    test "produces a CSR that parses back to the same algorithm and subject" do
      private_key = X509.PrivateKey.new_ec(:secp256r1)

      {:ok, pem} = Csr.generate("ECC-P256", private_key, "/CN=Classical Gen Test")

      assert {:ok, parsed} = Csr.parse(pem)
      assert parsed.algorithm_id == "ECC-P256"
      assert parsed.subject_dn =~ "CN=Classical Gen Test"
    end
  end

  describe "generate/3 for PQC" do
    test "KAZ-SIGN-192 CSR parses back correctly" do
      algo = PkiCrypto.Registry.get("KAZ-SIGN-192")
      {:ok, %{public_key: pub, private_key: priv}} = PkiCrypto.Algorithm.generate_keypair(algo)

      {:ok, pem} = Csr.generate("KAZ-SIGN-192", %{public_key: pub, private_key: priv}, "/CN=PQC Sub CA")

      assert {:ok, parsed} = Csr.parse(pem)
      assert parsed.algorithm_id == "KAZ-SIGN-192"
      assert parsed.subject_dn =~ "CN=PQC Sub CA"
      assert parsed.subject_public_key == pub
    end

    test "ML-DSA-44 CSR parses back correctly" do
      algo = PkiCrypto.Registry.get("ML-DSA-44")
      {:ok, %{public_key: pub, private_key: priv}} = PkiCrypto.Algorithm.generate_keypair(algo)

      {:ok, pem} = Csr.generate("ML-DSA-44", %{public_key: pub, private_key: priv}, "/CN=ML-DSA Test")

      assert {:ok, parsed} = Csr.parse(pem)
      assert parsed.algorithm_id == "ML-DSA-44"
      assert parsed.subject_public_key == pub
    end
  end
end
