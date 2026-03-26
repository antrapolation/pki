defmodule PkiCrypto.ShamirTest do
  use ExUnit.Case, async: true

  describe "split/3" do
    test "split(secret, 2, 3) returns 3 shares" do
      secret = :crypto.strong_rand_bytes(32)
      assert {:ok, shares} = PkiCrypto.Shamir.split(secret, 2, 3)
      assert length(shares) == 3
    end

    test "split with k < 2 fails" do
      secret = :crypto.strong_rand_bytes(32)
      assert {:error, :invalid_threshold} = PkiCrypto.Shamir.split(secret, 1, 3)
    end

    test "split with k > n fails" do
      secret = :crypto.strong_rand_bytes(32)
      assert {:error, :invalid_threshold} = PkiCrypto.Shamir.split(secret, 4, 3)
    end

    test "split(secret, k, k) works" do
      secret = :crypto.strong_rand_bytes(32)
      assert {:ok, shares} = PkiCrypto.Shamir.split(secret, 3, 3)
      assert length(shares) == 3
    end
  end

  describe "recover/1" do
    test "recover with k of n shares returns original secret" do
      secret = :crypto.strong_rand_bytes(32)
      {:ok, shares} = PkiCrypto.Shamir.split(secret, 2, 3)
      any_two = Enum.take(shares, 2)
      assert {:ok, ^secret} = PkiCrypto.Shamir.recover(any_two)
    end

    test "recover with any 2 of 3 shares works" do
      secret = :crypto.strong_rand_bytes(32)
      {:ok, [s1, s2, s3]} = PkiCrypto.Shamir.split(secret, 2, 3)
      assert {:ok, ^secret} = PkiCrypto.Shamir.recover([s1, s2])
      assert {:ok, ^secret} = PkiCrypto.Shamir.recover([s2, s3])
      assert {:ok, ^secret} = PkiCrypto.Shamir.recover([s1, s3])
    end

    test "split(secret, 3, 5) any 3 recover" do
      secret = :crypto.strong_rand_bytes(32)
      {:ok, shares} = PkiCrypto.Shamir.split(secret, 3, 5)
      assert length(shares) == 5
      subset = Enum.take(shares, 3)
      assert {:ok, ^secret} = PkiCrypto.Shamir.recover(subset)
    end

    test "large secret (256 bytes) works" do
      secret = :crypto.strong_rand_bytes(256)
      {:ok, shares} = PkiCrypto.Shamir.split(secret, 2, 3)
      assert {:ok, ^secret} = PkiCrypto.Shamir.recover(Enum.take(shares, 2))
    end
  end
end
