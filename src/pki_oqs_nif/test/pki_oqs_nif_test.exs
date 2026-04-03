defmodule PkiOqsNifTest do
  use ExUnit.Case, async: true
  import Bitwise

  @ml_dsa_algorithms ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
  @slh_dsa_algorithms [
    "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-128s",
    "SLH-DSA-SHA2-192f", "SLH-DSA-SHA2-192s",
    "SLH-DSA-SHA2-256f", "SLH-DSA-SHA2-256s"
  ]

  describe "keygen/1" do
    for algo <- ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"] do
      test "#{algo} generates valid keypair" do
        {:ok, %{public_key: pk, private_key: sk}} = PkiOqsNif.keygen(unquote(algo))
        assert is_binary(pk)
        assert is_binary(sk)
        assert byte_size(pk) > 0
        assert byte_size(sk) > 0
      end
    end

    for algo <- ["SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-128s"] do
      test "#{algo} generates valid keypair" do
        {:ok, %{public_key: pk, private_key: sk}} = PkiOqsNif.keygen(unquote(algo))
        assert is_binary(pk)
        assert is_binary(sk)
      end
    end

    test "returns error for unsupported algorithm" do
      assert {:error, :unsupported_algorithm} = PkiOqsNif.keygen("NONSENSE-ALGO")
    end
  end

  describe "sign/3 and verify/4 round-trip" do
    for algo <- ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"] do
      test "#{algo} sign then verify succeeds" do
        {:ok, %{public_key: pk, private_key: sk}} = PkiOqsNif.keygen(unquote(algo))
        message = "Hello post-quantum world!"
        {:ok, sig} = PkiOqsNif.sign(unquote(algo), sk, message)
        assert is_binary(sig)
        assert byte_size(sig) > 0
        assert :ok = PkiOqsNif.verify(unquote(algo), pk, sig, message)
      end
    end

    for algo <- ["SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-128s"] do
      test "#{algo} sign then verify succeeds" do
        {:ok, %{public_key: pk, private_key: sk}} = PkiOqsNif.keygen(unquote(algo))
        message = "SLH-DSA test message"
        {:ok, sig} = PkiOqsNif.sign(unquote(algo), sk, message)
        assert is_binary(sig)
        assert :ok = PkiOqsNif.verify(unquote(algo), pk, sig, message)
      end
    end
  end

  describe "verify/4 rejects invalid signatures" do
    test "ML-DSA-65 rejects wrong message" do
      {:ok, %{public_key: pk, private_key: sk}} = PkiOqsNif.keygen("ML-DSA-65")
      {:ok, sig} = PkiOqsNif.sign("ML-DSA-65", sk, "correct message")
      assert {:error, :invalid_signature} = PkiOqsNif.verify("ML-DSA-65", pk, sig, "wrong message")
    end

    test "ML-DSA-65 rejects tampered signature" do
      {:ok, %{public_key: pk, private_key: sk}} = PkiOqsNif.keygen("ML-DSA-65")
      {:ok, sig} = PkiOqsNif.sign("ML-DSA-65", sk, "test")
      # Flip a byte in the signature
      <<first_byte, rest::binary>> = sig
      tampered = <<bxor(first_byte, 0xFF), rest::binary>>
      assert {:error, :invalid_signature} = PkiOqsNif.verify("ML-DSA-65", pk, tampered, "test")
    end

    test "ML-DSA-65 rejects wrong public key" do
      {:ok, %{private_key: sk}} = PkiOqsNif.keygen("ML-DSA-65")
      {:ok, %{public_key: other_pk}} = PkiOqsNif.keygen("ML-DSA-65")
      {:ok, sig} = PkiOqsNif.sign("ML-DSA-65", sk, "test")
      assert {:error, :invalid_signature} = PkiOqsNif.verify("ML-DSA-65", other_pk, sig, "test")
    end
  end

  describe "edge cases" do
    test "sign empty message" do
      {:ok, %{public_key: pk, private_key: sk}} = PkiOqsNif.keygen("ML-DSA-44")
      {:ok, sig} = PkiOqsNif.sign("ML-DSA-44", sk, "")
      assert :ok = PkiOqsNif.verify("ML-DSA-44", pk, sig, "")
    end

    test "sign large message" do
      {:ok, %{public_key: pk, private_key: sk}} = PkiOqsNif.keygen("ML-DSA-44")
      large_msg = :crypto.strong_rand_bytes(1_000_000)
      {:ok, sig} = PkiOqsNif.sign("ML-DSA-44", sk, large_msg)
      assert :ok = PkiOqsNif.verify("ML-DSA-44", pk, sig, large_msg)
    end
  end
end
