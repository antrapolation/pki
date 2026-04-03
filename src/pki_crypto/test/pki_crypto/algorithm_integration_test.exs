defmodule PkiCrypto.AlgorithmIntegrationTest do
  @moduledoc """
  Integration tests for all registered algorithms via the PkiCrypto protocol.
  Tests the same code path used by key ceremonies: Registry.get → Algorithm.generate_keypair → sign → verify.
  """
  use ExUnit.Case, async: true

  alias PkiCrypto.{Registry, Algorithm}

  @test_message "Post-quantum cryptography test message for PKI CA system"
  @large_message :crypto.strong_rand_bytes(100_000)
  @empty_message ""

  # All signing algorithms from the registry
  @signing_algorithms [
    "RSA-4096",
    "ECC-P256",
    "ECC-P384",
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
    "SLH-DSA-SHA2-128f",
    "SLH-DSA-SHA2-128s",
    "SLH-DSA-SHA2-192f",
    "SLH-DSA-SHA2-192s",
    "SLH-DSA-SHA2-256f",
    "SLH-DSA-SHA2-256s"
  ]

  describe "registry" do
    test "all signing algorithms are registered" do
      for algo_name <- @signing_algorithms do
        algo = Registry.get(algo_name)
        assert algo != nil, "Algorithm #{algo_name} not found in registry"
        assert Algorithm.algorithm_type(algo) == :signing, "#{algo_name} should be :signing type"
        assert Algorithm.identifier(algo) == algo_name, "#{algo_name} identifier mismatch"
      end
    end

    test "registry contains expected total count" do
      all = Registry.all()
      # 12 signing + 1 KEM = 13
      assert map_size(all) == 13
    end

    test "signing_algorithms returns only signing type" do
      signing = Registry.signing_algorithms()
      assert map_size(signing) == 12

      for {_name, algo} <- signing do
        assert Algorithm.algorithm_type(algo) == :signing
      end
    end

    test "unknown algorithm returns nil" do
      assert Registry.get("NONEXISTENT") == nil
    end
  end

  describe "keygen via ceremony path (Registry.get → Algorithm.generate_keypair)" do
    for algo_name <- ["ECC-P256", "ECC-P384", "RSA-4096"] do
      test "#{algo_name} generates keypair via registry" do
        algo = Registry.get(unquote(algo_name))
        {:ok, %{public_key: pk, private_key: sk}} = Algorithm.generate_keypair(algo)
        assert is_binary(pk) and byte_size(pk) > 0
        assert is_binary(sk) and byte_size(sk) > 0
      end
    end

    for algo_name <- ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"] do
      test "#{algo_name} generates keypair via registry" do
        algo = Registry.get(unquote(algo_name))
        {:ok, %{public_key: pk, private_key: sk}} = Algorithm.generate_keypair(algo)
        assert is_binary(pk) and byte_size(pk) > 0
        assert is_binary(sk) and byte_size(sk) > 0
      end
    end

    for algo_name <- ["SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-128s"] do
      test "#{algo_name} generates keypair via registry" do
        algo = Registry.get(unquote(algo_name))
        {:ok, %{public_key: pk, private_key: sk}} = Algorithm.generate_keypair(algo)
        assert is_binary(pk) and byte_size(pk) > 0
        assert is_binary(sk) and byte_size(sk) > 0
      end
    end
  end

  describe "keygen → sign → verify round-trip (full ceremony path)" do
    for algo_name <- ["ECC-P256", "ECC-P384"] do
      test "#{algo_name} full round-trip" do
        algo = Registry.get(unquote(algo_name))
        {:ok, %{public_key: pk, private_key: sk}} = Algorithm.generate_keypair(algo)
        {:ok, sig} = Algorithm.sign(algo, sk, @test_message)
        assert is_binary(sig) and byte_size(sig) > 0
        assert :ok = Algorithm.verify(algo, pk, sig, @test_message)
      end
    end

    for algo_name <- ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"] do
      test "#{algo_name} full round-trip" do
        algo = Registry.get(unquote(algo_name))
        {:ok, %{public_key: pk, private_key: sk}} = Algorithm.generate_keypair(algo)
        {:ok, sig} = Algorithm.sign(algo, sk, @test_message)
        assert is_binary(sig) and byte_size(sig) > 0
        assert :ok = Algorithm.verify(algo, pk, sig, @test_message)
      end
    end

    for algo_name <- ["SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-128s"] do
      test "#{algo_name} full round-trip" do
        algo = Registry.get(unquote(algo_name))
        {:ok, %{public_key: pk, private_key: sk}} = Algorithm.generate_keypair(algo)
        {:ok, sig} = Algorithm.sign(algo, sk, @test_message)
        assert is_binary(sig) and byte_size(sig) > 0
        assert :ok = Algorithm.verify(algo, pk, sig, @test_message)
      end
    end
  end

  describe "signature rejection" do
    for algo_name <- ["ECC-P256", "ML-DSA-65", "SLH-DSA-SHA2-128f"] do
      test "#{algo_name} rejects wrong message" do
        algo = Registry.get(unquote(algo_name))
        {:ok, %{public_key: pk, private_key: sk}} = Algorithm.generate_keypair(algo)
        {:ok, sig} = Algorithm.sign(algo, sk, "correct message")
        assert {:error, :invalid_signature} = Algorithm.verify(algo, pk, sig, "wrong message")
      end

      test "#{algo_name} rejects wrong public key" do
        algo = Registry.get(unquote(algo_name))
        {:ok, %{private_key: sk}} = Algorithm.generate_keypair(algo)
        {:ok, %{public_key: other_pk}} = Algorithm.generate_keypair(algo)
        {:ok, sig} = Algorithm.sign(algo, sk, @test_message)
        assert {:error, :invalid_signature} = Algorithm.verify(algo, other_pk, sig, @test_message)
      end
    end
  end

  describe "edge cases" do
    test "ML-DSA-44 sign and verify empty message" do
      algo = Registry.get("ML-DSA-44")
      {:ok, %{public_key: pk, private_key: sk}} = Algorithm.generate_keypair(algo)
      {:ok, sig} = Algorithm.sign(algo, sk, @empty_message)
      assert :ok = Algorithm.verify(algo, pk, sig, @empty_message)
    end

    test "ML-DSA-65 sign and verify large message (100KB)" do
      algo = Registry.get("ML-DSA-65")
      {:ok, %{public_key: pk, private_key: sk}} = Algorithm.generate_keypair(algo)
      {:ok, sig} = Algorithm.sign(algo, sk, @large_message)
      assert :ok = Algorithm.verify(algo, pk, sig, @large_message)
    end

    test "ECC-P256 sign and verify empty message" do
      algo = Registry.get("ECC-P256")
      {:ok, %{public_key: pk, private_key: sk}} = Algorithm.generate_keypair(algo)
      {:ok, sig} = Algorithm.sign(algo, sk, @empty_message)
      assert :ok = Algorithm.verify(algo, pk, sig, @empty_message)
    end
  end

  describe "SyncCeremony.generate_keypair compatibility" do
    # Tests the exact code path used by the ceremony system
    for algo_name <- ["ECC-P256", "ML-DSA-65", "SLH-DSA-SHA2-128f"] do
      test "#{algo_name} via SyncCeremony.generate_keypair/1" do
        # This is exactly what the ceremony calls
        case PkiCrypto.Registry.get(unquote(algo_name)) do
          nil -> flunk("Algorithm #{unquote(algo_name)} not in registry")
          algo_struct ->
            {:ok, %{public_key: pk, private_key: sk}} = PkiCrypto.Algorithm.generate_keypair(algo_struct)
            assert is_binary(pk)
            assert is_binary(sk)

            # Verify the key can be used for signing
            {:ok, sig} = PkiCrypto.Algorithm.sign(algo_struct, sk, "ceremony test")
            assert :ok = PkiCrypto.Algorithm.verify(algo_struct, pk, sig, "ceremony test")
        end
      end
    end
  end

  describe "key sizes are correct" do
    test "ML-DSA-44 key sizes match FIPS 204 spec" do
      {:ok, %{public_key: pk, private_key: sk}} = Algorithm.generate_keypair(Registry.get("ML-DSA-44"))
      assert byte_size(pk) == 1312
      assert byte_size(sk) == 2560
    end

    test "ML-DSA-65 key sizes match FIPS 204 spec" do
      {:ok, %{public_key: pk, private_key: sk}} = Algorithm.generate_keypair(Registry.get("ML-DSA-65"))
      assert byte_size(pk) == 1952
      assert byte_size(sk) == 4032
    end

    test "ML-DSA-87 key sizes match FIPS 204 spec" do
      {:ok, %{public_key: pk, private_key: sk}} = Algorithm.generate_keypair(Registry.get("ML-DSA-87"))
      assert byte_size(pk) == 2592
      assert byte_size(sk) == 4896
    end

    test "SLH-DSA-SHA2-128f public key is 32 bytes" do
      {:ok, %{public_key: pk}} = Algorithm.generate_keypair(Registry.get("SLH-DSA-SHA2-128f"))
      assert byte_size(pk) == 32
    end
  end
end
