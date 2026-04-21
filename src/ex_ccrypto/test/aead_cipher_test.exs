defmodule AeadCipherTest do
  alias ExCcrypto.ContextConfig
  alias ExCcrypto.Cipher.CipherContextEncoder
  alias ExCcrypto.Cipher.CipherContextBuilder
  alias ExCcrypto.Cipher
  use ExUnit.Case

  test "Encrypt and decrypt with Cipher Context" do
    tbe_data = "this is sensitive data for encryption"

    for c <- [:aes_128_gcm, :aes_256_gcm, :aes_128_ccm, :aes_256_ccm, :chacha20_poly1305] do
      # for c <- [:aes_128_gcm] do
      IO.puts("Testing cipher : #{c}")

      {:ok, %{cipher: cipher, cipher_context: ctx, transient_key: key}} =
        CipherContextBuilder.cipher_context(c)
        |> Cipher.cipher_init()
        |> Cipher.cipher_update(tbe_data)
        |> Cipher.cipher_final()

      IO.puts("cipher output : ")
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

  test "Encrypt and decrypt with Cipher Context external key and iv" do
    tbe_data = "this is sensitive data for encryption"

    for c <- [:aes_128_gcm, :aes_256_gcm, :aes_128_ccm, :aes_256_ccm, :chacha20_poly1305] do
      IO.puts("Testing cipher : #{c}")

      cctx = CipherContextBuilder.cipher_context(c)
      key = :crypto.strong_rand_bytes(ContextConfig.get(cctx, :key_byte_size))
      iv = :crypto.strong_rand_bytes(ContextConfig.get(cctx, :iv_length))

      {:ok, %{cipher: cipher, cipher_context: ctx, transient_key: _tkey}} =
        cctx
        |> ContextConfig.set(:session_key, key)
        |> Cipher.cipher_init()
        |> Cipher.cipher_update(tbe_data)
        |> Cipher.cipher_final()

      IO.inspect(ctx)
      IO.inspect(cipher)

      assert(ContextConfig.get(ctx, :iv) != iv)

      {:ok, %{cipher: cipher2, cipher_context: ctx2, transient_key: _tkey}} =
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

  test "Chunk encrypt and decrypt with cipher context" do
    for c <- [:aes_128_gcm, :aes_256_gcm, :aes_128_ccm, :aes_256_ccm, :chacha20_poly1305] do
      IO.puts("Testing cipher : #{c}")

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

  test "Encrypt and decrypt with aead cipher context with AAD" do
    tbe_data = "this is sensitive data for encryption"
    # with aad
    aad = "user@domain.com"

    for c <- [:aes_128_gcm, :aes_256_gcm, :aes_128_ccm, :aes_256_ccm, :chacha20_poly1305] do
      IO.puts("Testing cipher : #{c}")

      {:ok, %{cipher: cipher, cipher_context: ctx, transient_key: key}} =
        CipherContextBuilder.cipher_context(c)
        |> ContextConfig.set(:aad, aad)
        |> Cipher.cipher_init()
        |> Cipher.cipher_update(tbe_data)
        |> Cipher.cipher_final()

      IO.inspect(ctx)

      # CipherContextBuilder.cipher_context(ctx)
      # |> ContextConfig.set(:aad, aad)
      {:ok, plain} =
        Cipher.cipher_init(ctx, %{aad: aad, session_key: key})
        |> Cipher.cipher_update(cipher)
        |> Cipher.cipher_final()

      assert(plain == tbe_data)

      # CipherContextBuilder.cipher_context(ctx)
      res =
        Cipher.cipher_init(ctx, %{session_key: key})
        |> Cipher.cipher_update(cipher)
        |> Cipher.cipher_final()

      assert(res == {:error, :decryption_failed})
    end
  end

  test "Encrypt and decrypt with aead cipher context with AAD and with cipher attached" do
    tbe_data = "this is sensitive data for encryption with cipher attached"
    # with aad
    aad = "user@domain.com"

    for c <- [:aes_128_gcm, :aes_256_gcm, :aes_128_ccm, :aes_256_ccm, :chacha20_poly1305] do
      IO.puts("Testing cipher : #{c}")

      {:ok, %{cipher_context: ctx, transient_key: key}} =
        CipherContextBuilder.cipher_context(c)
        |> ContextConfig.set(:aad, aad)
        |> ContextConfig.set(:attached_cipher?, true)
        |> Cipher.cipher_init()
        |> Cipher.cipher_update(tbe_data)
        |> Cipher.cipher_final()

      IO.inspect(ctx)

      {:ok, plain} =
        Cipher.cipher_init(ctx, %{aad: aad, session_key: key})
        |> Cipher.cipher_update()
        |> Cipher.cipher_final()

      assert(plain == tbe_data)

      # res =
      #  Cipher.cipher_init(ctx, %{session_key: key})
      #  |> Cipher.cipher_update(cipher)
      #  |> Cipher.cipher_final()

      # assert(res == {:error, :decryption_failed})
    end
  end
end
