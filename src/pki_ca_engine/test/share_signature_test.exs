defmodule PkiCaEngine.ShareSignatureTest do
  use ExUnit.Case, async: true

  alias PkiCaEngine.KeyCeremony.ShareEncryption

  @ceremony_id "ceremony-abc-123"
  @password "custodian-password-s3cret"
  @raw_share "this-is-a-raw-shamir-share-value"

  # Encrypt a share once and reuse the result across tests.
  setup do
    {:ok, encrypted} = ShareEncryption.encrypt_share(@raw_share, @password)
    signature = ShareEncryption.sign_share(encrypted, @ceremony_id)
    %{encrypted: encrypted, signature: signature}
  end

  describe "verify_share_signature/3" do
    test "valid share verifies and decrypts successfully", %{encrypted: encrypted, signature: signature} do
      # Signature check passes
      assert :ok = ShareEncryption.verify_share_signature(encrypted, signature, @ceremony_id)

      # Full decrypt also succeeds
      assert {:ok, plaintext} = ShareEncryption.decrypt_share(encrypted, @password)
      assert plaintext == @raw_share
    end

    test "tampered encrypted_share bytes return {:error, :invalid_signature}", %{encrypted: encrypted, signature: signature} do
      # Flip the last byte to simulate in-place tampering of the ciphertext blob.
      tampered_encrypted =
        binary_part(encrypted, 0, byte_size(encrypted) - 1) <>
          <<Bitwise.bxor(:binary.last(encrypted), 0xFF)>>

      assert {:error, :invalid_signature} =
               ShareEncryption.verify_share_signature(tampered_encrypted, signature, @ceremony_id)
    end

    test "swapped envelope (right share, wrong ceremony_id) returns {:error, :invalid_signature}",
         %{encrypted: encrypted, signature: signature} do
      wrong_ceremony_id = "ceremony-XYZ-999"

      # The signature was created for @ceremony_id; verifying against a different
      # ceremony_id must fail even though the encrypted bytes are untouched.
      assert {:error, :invalid_signature} =
               ShareEncryption.verify_share_signature(encrypted, signature, wrong_ceremony_id)
    end
  end

  describe "decrypt_share_verified/4" do
    test "valid share with correct password succeeds", %{encrypted: encrypted, signature: signature} do
      assert {:ok, plaintext} =
               ShareEncryption.decrypt_share_verified(encrypted, signature, @password, @ceremony_id)

      assert plaintext == @raw_share
    end

    test "tampered share short-circuits before decryption", %{encrypted: encrypted, signature: signature} do
      tampered_encrypted =
        binary_part(encrypted, 0, byte_size(encrypted) - 1) <>
          <<Bitwise.bxor(:binary.last(encrypted), 0xFF)>>

      assert {:error, :invalid_signature} =
               ShareEncryption.decrypt_share_verified(
                 tampered_encrypted, signature, @password, @ceremony_id
               )
    end

    test "wrong ceremony_id short-circuits before decryption", %{encrypted: encrypted, signature: signature} do
      assert {:error, :invalid_signature} =
               ShareEncryption.decrypt_share_verified(
                 encrypted, signature, @password, "wrong-ceremony-id"
               )
    end
  end
end
