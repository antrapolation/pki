defmodule PkiCaEngine.KeyCeremony.DefaultCryptoAdapterTest do
  use ExUnit.Case, async: true

  alias PkiCaEngine.KeyCeremony.{CryptoAdapter, DefaultCryptoAdapter}

  @adapter %DefaultCryptoAdapter{}

  # ── RSA keypair generation ─────────────────────────────────────

  describe "generate_keypair/2 RSA" do
    test "RSA-4096 returns {:ok, %{public_key, private_key}} with non-empty binaries" do
      assert {:ok, %{public_key: pub, private_key: priv}} =
               CryptoAdapter.generate_keypair(@adapter, "RSA-4096")

      assert is_binary(pub) and byte_size(pub) > 0
      assert is_binary(priv) and byte_size(priv) > 0
    end

    test "RSA-2048 returns valid keypair" do
      assert {:ok, %{public_key: pub, private_key: priv}} =
               CryptoAdapter.generate_keypair(@adapter, "RSA-2048")

      assert is_binary(pub) and byte_size(pub) > 0
      assert is_binary(priv) and byte_size(priv) > 0
    end

    test "RSA (default) returns valid keypair" do
      assert {:ok, %{public_key: pub, private_key: priv}} =
               CryptoAdapter.generate_keypair(@adapter, "RSA")

      assert is_binary(pub) and byte_size(pub) > 0
      assert is_binary(priv) and byte_size(priv) > 0
    end

    test "RSA private key is DER-encoded and decodable by :public_key" do
      {:ok, %{private_key: priv}} = CryptoAdapter.generate_keypair(@adapter, "RSA-2048")

      assert {:RSAPrivateKey, _, _, _, _, _, _, _, _, _, _} =
               :public_key.der_decode(:RSAPrivateKey, priv)
    end

    test "RSA public key is DER-encoded and decodable by :public_key" do
      {:ok, %{public_key: pub}} = CryptoAdapter.generate_keypair(@adapter, "RSA-2048")

      assert {:RSAPublicKey, modulus, exponent} = :public_key.der_decode(:RSAPublicKey, pub)
      assert is_integer(modulus)
      assert exponent == 65537
    end

    test "RSA generated keys are different each time (non-deterministic)" do
      {:ok, %{private_key: priv1}} = CryptoAdapter.generate_keypair(@adapter, "RSA-2048")
      {:ok, %{private_key: priv2}} = CryptoAdapter.generate_keypair(@adapter, "RSA-2048")

      refute priv1 == priv2
    end
  end

  # ── ECC keypair generation ─────────────────────────────────────

  describe "generate_keypair/2 ECC" do
    test "EC-P256 returns {:ok, %{public_key, private_key}} with non-empty binaries" do
      assert {:ok, %{public_key: pub, private_key: priv}} =
               CryptoAdapter.generate_keypair(@adapter, "EC-P256")

      assert is_binary(pub) and byte_size(pub) > 0
      assert is_binary(priv) and byte_size(priv) > 0
    end

    test "EC-P384 returns valid keypair" do
      assert {:ok, %{public_key: _pub, private_key: priv}} =
               CryptoAdapter.generate_keypair(@adapter, "EC-P384")

      assert is_binary(priv) and byte_size(priv) > 0
    end

    test "ECC (default) returns valid keypair" do
      assert {:ok, %{public_key: pub, private_key: priv}} =
               CryptoAdapter.generate_keypair(@adapter, "ECC")

      assert is_binary(pub) and byte_size(pub) > 0
      assert is_binary(priv) and byte_size(priv) > 0
    end

    test "ECDSA alias returns valid keypair" do
      assert {:ok, %{public_key: _pub, private_key: priv}} =
               CryptoAdapter.generate_keypair(@adapter, "ECDSA")

      assert is_binary(priv) and byte_size(priv) > 0
    end

    test "EC private key is DER-encoded and decodable by :public_key" do
      {:ok, %{private_key: priv}} = CryptoAdapter.generate_keypair(@adapter, "EC-P256")

      assert {:ECPrivateKey, _, _, _, _, _} = :public_key.der_decode(:ECPrivateKey, priv)
    end

    test "EC generated keys are different each time (non-deterministic)" do
      {:ok, %{private_key: priv1}} = CryptoAdapter.generate_keypair(@adapter, "EC-P256")
      {:ok, %{private_key: priv2}} = CryptoAdapter.generate_keypair(@adapter, "EC-P256")

      refute priv1 == priv2
    end
  end

  # ── Unsupported algorithms ─────────────────────────────────────

  describe "generate_keypair/2 unsupported algorithms" do
    test "returns error for unsupported string algorithm" do
      assert {:error, {:unsupported_algorithm, "ML-DSA-65"}} =
               CryptoAdapter.generate_keypair(@adapter, "ML-DSA-65")
    end

    test "returns error for KAZ-SIGN (not yet implemented)" do
      assert {:error, {:unsupported_algorithm, "KAZ-SIGN-256"}} =
               CryptoAdapter.generate_keypair(@adapter, "KAZ-SIGN-256")
    end

    test "returns error for arbitrary unknown algorithm" do
      assert {:error, {:unsupported_algorithm, "QUANTUM-MAGIC"}} =
               CryptoAdapter.generate_keypair(@adapter, "QUANTUM-MAGIC")
    end

    test "returns error for non-string algorithm" do
      assert {:error, {:unsupported_algorithm, 42}} =
               CryptoAdapter.generate_keypair(@adapter, 42)
    end

    test "algorithm matching is case-insensitive" do
      assert {:ok, _} = CryptoAdapter.generate_keypair(@adapter, "rsa-2048")
      assert {:ok, _} = CryptoAdapter.generate_keypair(@adapter, "RSA-2048")
      assert {:ok, _} = CryptoAdapter.generate_keypair(@adapter, "Rsa-2048")
    end
  end

  # ── Shamir secret splitting and recovery ───────────────────────

  describe "split_secret/4 and recover_secret/2" do
    test "split then recover returns original secret" do
      secret = :crypto.strong_rand_bytes(64)

      {:ok, shares} = CryptoAdapter.split_secret(@adapter, secret, 2, 3)
      assert length(shares) == 3

      # Recover with threshold K=2 shares
      {:ok, recovered} = CryptoAdapter.recover_secret(@adapter, Enum.take(shares, 2))
      assert recovered == secret
    end

    test "recovery works with any K-subset of N shares" do
      secret = :crypto.strong_rand_bytes(32)
      {:ok, shares} = CryptoAdapter.split_secret(@adapter, secret, 2, 3)

      # Try all 2-element subsets of 3 shares
      for combo <- combinations(shares, 2) do
        {:ok, recovered} = CryptoAdapter.recover_secret(@adapter, combo)
        assert recovered == secret
      end
    end

    test "split with K=3, N=5 produces 5 shares" do
      secret = :crypto.strong_rand_bytes(16)
      {:ok, shares} = CryptoAdapter.split_secret(@adapter, secret, 3, 5)
      assert length(shares) == 5
    end
  end

  # ── Integration: keypair generation + split/recover round-trip ─

  describe "end-to-end: generate keypair, split private key, recover" do
    test "RSA private key survives Shamir split and recovery" do
      {:ok, %{private_key: priv}} = CryptoAdapter.generate_keypair(@adapter, "RSA-2048")

      {:ok, shares} = CryptoAdapter.split_secret(@adapter, priv, 2, 3)
      {:ok, recovered} = CryptoAdapter.recover_secret(@adapter, Enum.take(shares, 2))

      assert recovered == priv

      # Verify recovered key is still valid DER
      assert {:RSAPrivateKey, _, _, _, _, _, _, _, _, _, _} =
               :public_key.der_decode(:RSAPrivateKey, recovered)
    end

    test "EC private key survives Shamir split and recovery" do
      {:ok, %{private_key: priv}} = CryptoAdapter.generate_keypair(@adapter, "EC-P256")

      {:ok, shares} = CryptoAdapter.split_secret(@adapter, priv, 2, 3)
      {:ok, recovered} = CryptoAdapter.recover_secret(@adapter, Enum.take(shares, 2))

      assert recovered == priv

      # Verify recovered key is still valid DER
      assert {:ECPrivateKey, _, _, _, _, _} = :public_key.der_decode(:ECPrivateKey, recovered)
    end
  end

  # ── Helpers ────────────────────────────────────────────────────

  defp combinations(_, 0), do: [[]]
  defp combinations([], _), do: []

  defp combinations([head | tail], k) do
    for(combo <- combinations(tail, k - 1), do: [head | combo]) ++ combinations(tail, k)
  end
end
