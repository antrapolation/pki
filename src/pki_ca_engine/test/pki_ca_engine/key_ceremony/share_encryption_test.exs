defmodule PkiCaEngine.KeyCeremony.ShareEncryptionTest do
  use ExUnit.Case, async: true

  alias PkiCaEngine.KeyCeremony.ShareEncryption

  describe "encrypt_share/2" do
    test "encrypts binary share with a password string" do
      share = :crypto.strong_rand_bytes(32)
      password = "custodian-password-123"

      assert {:ok, encrypted} = ShareEncryption.encrypt_share(share, password)
      assert is_binary(encrypted)
      # encrypted should be larger than original (salt + iv + tag + ciphertext)
      assert byte_size(encrypted) > byte_size(share)
    end

    test "produces different ciphertexts for same input (random salt/iv)" do
      share = "same-secret-share-data"
      password = "same-password"

      {:ok, encrypted1} = ShareEncryption.encrypt_share(share, password)
      {:ok, encrypted2} = ShareEncryption.encrypt_share(share, password)

      refute encrypted1 == encrypted2
    end
  end

  describe "decrypt_share/2" do
    test "decrypts with correct password returns original share" do
      share = :crypto.strong_rand_bytes(48)
      password = "correct-password"

      {:ok, encrypted} = ShareEncryption.encrypt_share(share, password)
      assert {:ok, decrypted} = ShareEncryption.decrypt_share(encrypted, password)
      assert decrypted == share
    end

    test "with wrong password returns {:error, :decryption_failed}" do
      share = "secret-share-data"
      password = "correct-password"
      wrong_password = "wrong-password"

      {:ok, encrypted} = ShareEncryption.encrypt_share(share, password)
      assert {:error, :decryption_failed} = ShareEncryption.decrypt_share(encrypted, wrong_password)
    end
  end

  describe "truncated ciphertext (D15 regression)" do
    test "returns {:error, :invalid_data} for truncated binary" do
      # Minimum valid encrypted binary is 44 bytes (16 salt + 12 iv + 16 tag + 0 ciphertext)
      truncated = :crypto.strong_rand_bytes(10)
      assert {:error, :invalid_data} = ShareEncryption.decrypt_share(truncated, "password")
    end

    test "returns {:error, :invalid_data} for empty binary" do
      assert {:error, :invalid_data} = ShareEncryption.decrypt_share(<<>>, "password")
    end

    test "returns {:error, :invalid_data} for binary just under minimum size" do
      # 43 bytes is 1 byte short of minimum (16 + 12 + 16 = 44)
      truncated = :crypto.strong_rand_bytes(43)
      assert {:error, :invalid_data} = ShareEncryption.decrypt_share(truncated, "password")
    end
  end

  describe "password isolation" do
    test "different passwords produce different ciphertext for same plaintext" do
      share = "same-share-data-for-comparison"
      password_a = "password-alpha"
      password_b = "password-beta"

      {:ok, encrypted_a} = ShareEncryption.encrypt_share(share, password_a)
      {:ok, encrypted_b} = ShareEncryption.encrypt_share(share, password_b)

      # Ciphertexts must differ (different derived keys even ignoring random salt/iv)
      refute encrypted_a == encrypted_b

      # Each decrypts only with its own password
      assert {:ok, ^share} = ShareEncryption.decrypt_share(encrypted_a, password_a)
      assert {:error, :decryption_failed} = ShareEncryption.decrypt_share(encrypted_a, password_b)
      assert {:ok, ^share} = ShareEncryption.decrypt_share(encrypted_b, password_b)
      assert {:error, :decryption_failed} = ShareEncryption.decrypt_share(encrypted_b, password_a)
    end
  end

  describe "large data encryption" do
    test "encrypt then decrypt works with large binary (1 MB)" do
      share = :crypto.strong_rand_bytes(1_000_000)
      password = "large-data-password"

      {:ok, encrypted} = ShareEncryption.encrypt_share(share, password)
      assert {:ok, decrypted} = ShareEncryption.decrypt_share(encrypted, password)
      assert decrypted == share
    end
  end

  describe "round-trip" do
    test "encrypt then decrypt recovers original binary for various sizes" do
      password = "round-trip-password"

      for size <- [1, 16, 32, 64, 128, 256] do
        share = :crypto.strong_rand_bytes(size)
        {:ok, encrypted} = ShareEncryption.encrypt_share(share, password)
        {:ok, decrypted} = ShareEncryption.decrypt_share(encrypted, password)
        assert decrypted == share, "Failed round-trip for share size #{size}"
      end
    end

    test "encrypt then decrypt works with empty binary" do
      password = "password"
      share = <<>>

      {:ok, encrypted} = ShareEncryption.encrypt_share(share, password)
      {:ok, decrypted} = ShareEncryption.decrypt_share(encrypted, password)
      assert decrypted == share
    end
  end
end
