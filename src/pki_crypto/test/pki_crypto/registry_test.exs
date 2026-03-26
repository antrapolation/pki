defmodule PkiCrypto.RegistryTest do
  use ExUnit.Case, async: true

  describe "get/1" do
    test "returns RSA-4096 struct" do
      assert %PkiCrypto.Signing.RSA4096{} = PkiCrypto.Registry.get("RSA-4096")
    end

    test "returns ECC-P256 struct" do
      assert %PkiCrypto.Signing.ECCP256{} = PkiCrypto.Registry.get("ECC-P256")
    end

    test "returns ECC-P384 struct" do
      assert %PkiCrypto.Signing.ECCP384{} = PkiCrypto.Registry.get("ECC-P384")
    end

    test "returns ECDH-P256 struct" do
      assert %PkiCrypto.Kem.ECDHP256{} = PkiCrypto.Registry.get("ECDH-P256")
    end

    test "returns nil for unknown" do
      assert nil == PkiCrypto.Registry.get("unknown")
    end
  end

  describe "signing_algorithms/0" do
    test "returns only signing types" do
      signing = PkiCrypto.Registry.signing_algorithms()
      assert map_size(signing) >= 3
      for {_name, algo} <- signing do
        assert PkiCrypto.Algorithm.algorithm_type(algo) == :signing
      end
    end
  end

  describe "kem_algorithms/0" do
    test "returns only KEM types" do
      kem = PkiCrypto.Registry.kem_algorithms()
      assert map_size(kem) >= 1
      for {_name, algo} <- kem do
        assert PkiCrypto.Algorithm.algorithm_type(algo) == :kem
      end
    end
  end

  describe "all/0" do
    test "returns complete map" do
      all = PkiCrypto.Registry.all()
      assert map_size(all) >= 4
      assert Map.has_key?(all, "RSA-4096")
      assert Map.has_key?(all, "ECDH-P256")
    end

    test "every registered algorithm can generate a keypair" do
      for {name, algo} <- PkiCrypto.Registry.all() do
        assert {:ok, %{public_key: pub, private_key: priv}} = PkiCrypto.Algorithm.generate_keypair(algo),
               "#{name} failed generate_keypair"
        assert is_binary(pub) and is_binary(priv)
      end
    end
  end
end
