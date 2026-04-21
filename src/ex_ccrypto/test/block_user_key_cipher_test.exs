defmodule BlockUserKeyCipherTest do
  alias ExCcrypto.ContextConfig
  alias ExCcrypto.Cipher.CipherContextBuilder
  alias ExCcrypto.Cipher
  use ExUnit.Case

  test "Encrypt and decrypt with Block Cipher Context with user key" do
    tbe_data = "this is sensitive data for encryption protected by user key"

    for c <- [:aes_128_cbc, :aes_256_ctr, :aes_256_ofb] do
      IO.puts("Testing block cipher : #{c}")

      {:ok, %{cipher: cipher, cipher_context: ctx, transient_key: key}} =
        CipherContextBuilder.user_key_cipher_context(c, "p@ssw0rd")
        |> Cipher.cipher_init()
        |> Cipher.cipher_update(tbe_data)
        |> Cipher.cipher_final()

      IO.inspect(ctx)
      IO.inspect(cipher)

      assert(ContextConfig.get(ctx, :iv) != nil)

      {:ok, plain} =
        Cipher.cipher_init(ctx, %{password: "p@ssw0rd"})
        |> Cipher.cipher_update(cipher)
        |> Cipher.cipher_final()

      assert(plain == tbe_data)
    end
  end

  test "Chunk encrypt and decrypt with cipher context with user key" do
    for c <- [:aes_128_cbc, :aes_256_ctr, :aes_256_ofb] do
      {:ok, %{cipher: cipher, cipher_context: ctx, transient_key: key}} =
        CipherContextBuilder.user_key_cipher_context(c, "p@ssw0rd")
        |> Cipher.cipher_init()
        |> Cipher.cipher_update("first batch")
        |> Cipher.cipher_update(" second batch")
        |> Cipher.cipher_update(" third batch")
        |> Cipher.cipher_final()

      IO.inspect(ctx)

      {:ok, plain} =
        Cipher.cipher_init(ctx, %{password: "p@ssw0rd"})
        |> Cipher.cipher_update(cipher)
        |> Cipher.cipher_final()

      assert(plain == "first batch second batch third batch")
    end
  end

  test "Encrypt and decrypt with Block Cipher Context and attached cipher with user key" do
    tbe_data = "this is sensitive data for encryption with cipher attached and user key"

    for c <- [:aes_128_cbc, :aes_256_ctr, :aes_256_ofb] do
      IO.puts("Testing cipher : #{c}")

      {:ok, %{cipher_context: ctx, transient_key: key}} =
        CipherContextBuilder.user_key_cipher_context(c, "p@ssw0rd")
        |> ContextConfig.set(:attached_cipher?, true)
        |> Cipher.cipher_init()
        |> Cipher.cipher_update(tbe_data)
        |> Cipher.cipher_final()

      IO.inspect(ctx)

      {:ok, plain} =
        Cipher.cipher_init(ctx, %{password: "p@ssw0rd"})
        |> Cipher.cipher_update()
        |> Cipher.cipher_final()

      assert(plain == tbe_data)
    end
  end
end
