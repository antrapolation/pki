defmodule BlockCipherTest do
  alias ExCcrypto.ContextConfig
  alias ExCcrypto.Cipher.CipherContextBuilder
  alias ExCcrypto.Cipher
  use ExUnit.Case

  test "Encrypt and decrypt with Block Cipher Context" do
    tbe_data = "this is sensitive data for encryption"

    for c <- [:aes_128_cbc, :aes_256_ctr, :aes_256_ofb] do
      IO.puts("Testing cipher : #{c}")

      {:ok, %{cipher: cipher, cipher_context: ctx, transient_key: key}} =
        CipherContextBuilder.cipher_context(c)
        |> Cipher.cipher_init()
        |> Cipher.cipher_update(tbe_data)
        |> Cipher.cipher_final()

      IO.inspect(ctx)
      IO.inspect(cipher)

      assert(ContextConfig.get(ctx, :iv) != nil)

      {:ok, plain} =
        Cipher.cipher_init(ctx, %{session_key: key})
        |> Cipher.cipher_update(cipher)
        |> Cipher.cipher_final()

      assert(plain == tbe_data)
    end
  end

  test "Chunk encrypt and decrypt with cipher context" do
    for c <- [:aes_128_cbc, :aes_256_ctr, :aes_256_ofb] do
      {:ok, %{cipher: cipher, cipher_context: ctx, transient_key: key}} =
        CipherContextBuilder.cipher_context(c)
        |> Cipher.cipher_init()
        |> Cipher.cipher_update("first batch")
        |> Cipher.cipher_update(" second batch")
        |> Cipher.cipher_update(" third batch")
        |> Cipher.cipher_final()

      IO.inspect(ctx)

      {:ok, plain} =
        Cipher.cipher_init(ctx, %{session_key: key})
        |> Cipher.cipher_update(cipher)
        |> Cipher.cipher_final()

      assert(plain == "first batch second batch third batch")
    end
  end

  test "Encrypt and decrypt with Cipher Context external key and iv" do
    tbe_data = "this is sensitive data for encryption"

    for c <- [:aes_128_cbc, :aes_256_ctr, :aes_256_ofb] do
      IO.puts("Testing cipher : #{c}")

      cctx = CipherContextBuilder.cipher_context(c)
      key = :crypto.strong_rand_bytes(ContextConfig.get(cctx, :key_byte_size))
      iv = :crypto.strong_rand_bytes(ContextConfig.get(cctx, :iv_length))

      {:ok, %{cipher: cipher, cipher_context: ctx, transient_key: _key}} =
        cctx
        |> ContextConfig.set(:session_key, key)
        |> Cipher.cipher_init()
        |> Cipher.cipher_update(tbe_data)
        |> Cipher.cipher_final()

      IO.inspect(ctx)
      IO.inspect(cipher)

      assert(ContextConfig.get(ctx, :iv) != iv)

      {:ok, %{cipher: cipher2, cipher_context: ctx2, transient_key: _key}} =
        cctx
        |> ContextConfig.set(:session_key, key)
        |> ContextConfig.set(:iv, iv)
        |> Cipher.cipher_init()
        |> Cipher.cipher_update(tbe_data)
        |> Cipher.cipher_final()

      IO.puts("ctx2 : ")
      IO.inspect(ctx2)

      assert(ContextConfig.get(ctx2, :iv) == nil)

      {:ok, plain} =
        Cipher.cipher_init(ctx, %{session_key: key})
        |> Cipher.cipher_update(cipher)
        |> Cipher.cipher_final()

      assert(plain == tbe_data)

      {:ok, plain2} =
        Cipher.cipher_init(ctx, %{session_key: key, iv: iv})
        |> Cipher.cipher_update(cipher2)
        |> Cipher.cipher_final()

      assert(plain2 == tbe_data)

      res = Cipher.cipher_init(ctx)

      IO.inspect(res)
      # no key given
      assert(res == {:error, :decryption_key_is_required})

      res2 = Cipher.cipher_init(ctx2, %{session_key: key})

      IO.inspect(res2)
      # no iv given
      assert(res2 == {:error, :decryption_iv_is_required})
    end
  end

  test "Encrypt and decrypt with Block Cipher Context and attached cipher" do
    tbe_data = "this is sensitive data for encryption with cipher attached"

    for c <- [:aes_128_cbc, :aes_256_ctr, :aes_256_ofb] do
      IO.puts("Testing cipher : #{c}")

      {:ok, %{cipher_context: ctx, transient_key: key}} =
        CipherContextBuilder.cipher_context(c)
        |> ContextConfig.set(:attached_cipher?, true)
        |> Cipher.cipher_init()
        |> Cipher.cipher_update(tbe_data)
        |> Cipher.cipher_final()

      IO.inspect(ctx)

      {:ok, plain} =
        Cipher.cipher_init(ctx, %{session_key: key})
        |> Cipher.cipher_update()
        |> Cipher.cipher_final()

      assert(plain == tbe_data)
    end
  end
end
