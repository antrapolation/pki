defmodule PkiValidation.Crypto.Signer.MlDsaTest do
  use ExUnit.Case, async: true

  describe "MlDsa44 behaviour conformance" do
    alias PkiValidation.Crypto.Signer.MlDsa44

    test "sign/verify round-trip via pki_crypto NIF" do
      algo = PkiCrypto.Registry.get("ML-DSA-44")
      {:ok, %{public_key: pk, private_key: sk}} = PkiCrypto.Algorithm.generate_keypair(algo)

      tbs = "tbs-bytes-placeholder"
      decoded = MlDsa44.decode_private_key(sk)
      assert is_binary(decoded)

      signature = MlDsa44.sign(tbs, decoded)
      assert is_binary(signature)
      assert byte_size(signature) > 0

      assert :ok = PkiCrypto.Algorithm.verify(algo, pk, signature, tbs)
    end

    test "algorithm_identifier_der/0 emits SEQUENCE(OID) DER" do
      der = MlDsa44.algorithm_identifier_der()
      assert <<0x30, _total_len, 0x06, _oid_len, _rest::binary>> = der
    end

    test "algorithm_identifier_record/0 is a 3-tuple :AlgorithmIdentifier" do
      assert {:AlgorithmIdentifier, {2, 16, 840, 1, 101, 3, 4, 3, 17}, :asn1_NOVALUE} =
               MlDsa44.algorithm_identifier_record()
    end
  end

  describe "MlDsa65 behaviour conformance" do
    alias PkiValidation.Crypto.Signer.MlDsa65

    test "sign/verify round-trip" do
      algo = PkiCrypto.Registry.get("ML-DSA-65")
      {:ok, %{public_key: pk, private_key: sk}} = PkiCrypto.Algorithm.generate_keypair(algo)
      signature = MlDsa65.sign("tbs-65", MlDsa65.decode_private_key(sk))
      assert :ok = PkiCrypto.Algorithm.verify(algo, pk, signature, "tbs-65")
    end

    test "algorithm_identifier_record uses OID 2.16.840.1.101.3.4.3.18" do
      assert {:AlgorithmIdentifier, {2, 16, 840, 1, 101, 3, 4, 3, 18}, :asn1_NOVALUE} =
               MlDsa65.algorithm_identifier_record()
    end
  end

  describe "MlDsa87 behaviour conformance" do
    alias PkiValidation.Crypto.Signer.MlDsa87

    test "sign/verify round-trip" do
      algo = PkiCrypto.Registry.get("ML-DSA-87")
      {:ok, %{public_key: pk, private_key: sk}} = PkiCrypto.Algorithm.generate_keypair(algo)
      signature = MlDsa87.sign("tbs-87", MlDsa87.decode_private_key(sk))
      assert :ok = PkiCrypto.Algorithm.verify(algo, pk, signature, "tbs-87")
    end

    test "algorithm_identifier_record uses OID 2.16.840.1.101.3.4.3.19" do
      assert {:AlgorithmIdentifier, {2, 16, 840, 1, 101, 3, 4, 3, 19}, :asn1_NOVALUE} =
               MlDsa87.algorithm_identifier_record()
    end
  end
end
