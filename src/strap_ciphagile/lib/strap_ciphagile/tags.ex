defmodule StrapCiphagile.Tags do
  @magic <<0xAF, 0x08>>

  # first byte
  @hash_envp 0x01
  @kdf_envp 0x02
  @threshold_envp 0x04

  @signature_envp 0x08
  @symkey_cipher_envp 0x0A
  @cipher_payload_envp 0x09
  @asymkey_cipher_envp 0x0B

  @secret_key_envp 0x10
  @pubkey_envp 0x11
  @privkey_envp 0x12

  def tag_value(:magic), do: {:ok, @magic}
  def tag_value(:hash_envp), do: {:ok, @hash_envp}
  def tag_value(:kdf_envp), do: {:ok, @kdf_envp}
  def tag_value(:threshold_envp), do: {:ok, @threshold_envp}
  def tag_value(:signature_envp), do: {:ok, @signature_envp}
  def tag_value(:symkey_cipher_envp), do: {:ok, @symkey_cipher_envp}
  def tag_value(:cipher_payload_envp), do: {:ok, @cipher_payload_envp}
  def tag_value(:asymkey_cipher_envp), do: {:ok, @asymkey_cipher_envp}
  def tag_value(:secret_key_envp), do: {:ok, @secret_key_envp}
  def tag_value(:pubkey_envp), do: {:ok, @pubkey_envp}
  def tag_value(:privkey_envp), do: {:ok, @privkey_envp}

  def tag_value(val), do: {:error, {:no_tag_defined, val}}
end
