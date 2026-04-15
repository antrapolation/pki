defmodule PkiValidation.Crypto.Signer.KazSignTest do
  use ExUnit.Case, async: true

  describe "KazSign128 behaviour conformance" do
    alias PkiValidation.Crypto.Signer.KazSign128

    test "sign/verify round-trip via pki_crypto" do
      algo = PkiCrypto.Registry.get("KAZ-SIGN-128")
      {:ok, %{public_key: pk, private_key: sk}} = PkiCrypto.Algorithm.generate_keypair(algo)

      tbs = "tbs-bytes"
      signature = KazSign128.sign(tbs, KazSign128.decode_private_key(sk))
      assert is_binary(signature) and byte_size(signature) > 0

      assert :ok = PkiCrypto.Algorithm.verify(algo, pk, signature, tbs)
    end

    test "algorithm_identifier_record uses placeholder OID" do
      assert {:AlgorithmIdentifier, {1, 3, 6, 1, 4, 1, 99999, 1, 1, 1}, :asn1_NOVALUE} =
               KazSign128.algorithm_identifier_record()
    end

    test "algorithm_identifier_der starts with SEQUENCE + OID tag" do
      <<0x30, _len, 0x06, _oid_len, _rest::binary>> = KazSign128.algorithm_identifier_der()
    end
  end

  describe "KazSign192 behaviour conformance" do
    alias PkiValidation.Crypto.Signer.KazSign192

    test "sign/verify round-trip" do
      algo = PkiCrypto.Registry.get("KAZ-SIGN-192")
      {:ok, %{public_key: pk, private_key: sk}} = PkiCrypto.Algorithm.generate_keypair(algo)
      signature = KazSign192.sign("tbs-192", KazSign192.decode_private_key(sk))
      assert :ok = PkiCrypto.Algorithm.verify(algo, pk, signature, "tbs-192")
    end

    test "algorithm_identifier_record uses placeholder OID .2" do
      assert {:AlgorithmIdentifier, {1, 3, 6, 1, 4, 1, 99999, 1, 1, 2}, :asn1_NOVALUE} =
               KazSign192.algorithm_identifier_record()
    end
  end

  describe "KazSign256 behaviour conformance" do
    alias PkiValidation.Crypto.Signer.KazSign256

    test "sign/verify round-trip" do
      algo = PkiCrypto.Registry.get("KAZ-SIGN-256")
      {:ok, %{public_key: pk, private_key: sk}} = PkiCrypto.Algorithm.generate_keypair(algo)
      signature = KazSign256.sign("tbs-256", KazSign256.decode_private_key(sk))
      assert :ok = PkiCrypto.Algorithm.verify(algo, pk, signature, "tbs-256")
    end

    test "algorithm_identifier_record uses placeholder OID .3" do
      assert {:AlgorithmIdentifier, {1, 3, 6, 1, 4, 1, 99999, 1, 1, 3}, :asn1_NOVALUE} =
               KazSign256.algorithm_identifier_record()
    end
  end
end
