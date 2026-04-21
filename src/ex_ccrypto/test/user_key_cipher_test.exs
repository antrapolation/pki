defmodule UserKeyCipherTest do
  alias ExCcrypto.ContextConfig
  alias ExCcrypto.Cipher.CipherContextEncoder
  alias ExCcrypto.Cipher.CipherContextBuilder
  alias ExCcrypto.Cipher
  use ExUnit.Case

  test "Encrypt and decrypt with selected AEAD cipher context with user key" do
    tbe_data = "this is sensitive data to encrypt for selected AEAD cipher context with user key"

    case CipherContextBuilder.user_key_cipher_context(:aes_256_gcm, "password") do
      {:error, reason} ->
        {:error, reason}

      ctx ->
        {:ok, %{cipher: cipher, cipher_context: ectx, transient_key: key}} =
          Cipher.cipher_init(ctx)
          |> Cipher.cipher_update(tbe_data)
          |> Cipher.cipher_final()

        # IO.puts("cipher output : ")
        # IO.inspect(ctx)
        # IO.inspect(cipher)

        case ContextConfig.get(ectx, :iv_length) > 0 do
          true ->
            assert(ContextConfig.get(ectx, :iv) != nil)

          _ ->
            nil
        end

        {:ok, plain} =
          Cipher.cipher_init(ectx, %{password: "password"})
          |> Cipher.cipher_update(cipher)
          |> Cipher.cipher_final()

        IO.puts("AEAD cipher decrypted : #{plain}")
        assert(plain == tbe_data)

        {:ok, %{cipher: cipher2, cipher_context: ctx2, transient_key: key2}} =
          Cipher.cipher(ctx, tbe_data)

        {:ok, plain2} = Cipher.cipher(ctx2, cipher2, %{session_key: key2})
        assert(plain2 == plain)
    end
  end

  test "Encrypt and decrypt with selected block cipher context with user key" do
    tbe_data = "this is sensitive data to encrypt for selected block cipher context"

    case CipherContextBuilder.user_key_cipher_context(:aes_256_cbc, "password") do
      {:error, reason} ->
        {:error, reason}

      ctx ->
        {:ok, %{cipher: cipher, cipher_context: ectx, transient_key: key}} =
          Cipher.cipher_init(ctx)
          |> Cipher.cipher_update(tbe_data)
          |> Cipher.cipher_final()

        case ContextConfig.get(ectx, :iv_length) > 0 do
          true ->
            assert(ContextConfig.get(ectx, :iv) != nil)

          _ ->
            nil
        end

        {:ok, plain} =
          Cipher.cipher_init(ectx, %{password: "password"})
          |> Cipher.cipher_update(cipher)
          |> Cipher.cipher_final()

        IO.puts("block cipher decrypted : #{plain}")
        assert(plain == tbe_data)

        {:ok, %{cipher: cipher2, cipher_context: ctx2, transient_key: key2}} =
          Cipher.cipher(ctx, tbe_data)

        {:ok, plain2} = Cipher.cipher(ctx2, cipher2, %{password: "password"})
        assert(plain2 == plain)
    end
  end

  test "Encrypt and decrypt with all supported cipher context wit user key" do
    tbe_data = "this is sensitive data to encrypt for all supported cipher context"

    for c <- CipherContextBuilder.supported_ciphers() do
      # for c <- [:aes_128_gcm] do
      IO.puts("Testing cipher : #{c}")

      case CipherContextBuilder.user_key_cipher_context(c, "p@ssw0rd") do
        {:error, reason} ->
          {:error, reason}

        ctx ->
          {:ok, %{cipher: cipher, cipher_context: ectx, transient_key: key}} =
            Cipher.cipher_init(ctx)
            |> Cipher.cipher_update(tbe_data)
            |> Cipher.cipher_final()

          # IO.puts("cipher output : ")
          # IO.inspect(ctx)
          # IO.inspect(cipher)

          case ContextConfig.get(ectx, :iv_length) > 0 do
            true ->
              assert(ContextConfig.get(ectx, :iv) != nil)

            _ ->
              nil
          end

          {:ok, plain} =
            Cipher.cipher_init(ectx, %{password: "p@ssw0rd"})
            |> Cipher.cipher_update(cipher)
            |> Cipher.cipher_final()

          assert(plain == tbe_data)

          {:ok, %{cipher: cipher2, cipher_context: ctx2, transient_key: key2}} =
            Cipher.cipher(ctx, tbe_data)

          {:ok, plain2} = Cipher.cipher(ctx2, cipher2, %{password: "p@ssw0rd"})
          assert(plain2 == plain)
      end
    end
  end

  test "Encrypt and decrypt with all supported Cipher Context with external iv" do
    tbe_data = "this is sensitive data for encryption"

    for c <- CipherContextBuilder.supported_ciphers() do
      IO.puts("Testing cipher : #{c}")

      case CipherContextBuilder.user_key_cipher_context(c, "p@ssw0rd") do
        {:error, reason} ->
          {:error, reason}

        cctx ->
          iv = :crypto.strong_rand_bytes(ContextConfig.get(cctx, :iv_length))

          {:ok, %{cipher: cipher, cipher_context: ctx, transient_key: rkey}} =
            cctx
            |> Cipher.cipher_init()
            |> Cipher.cipher_update(tbe_data)
            |> Cipher.cipher_final()

          # IO.inspect(ctx)
          # IO.inspect(cipher)

          case ContextConfig.get(ctx, :iv_length) > 0 do
            true ->
              assert(ContextConfig.get(ctx, :iv) != nil)

            _ ->
              nil
          end

          {:ok, %{cipher: cipher2, cipher_context: ctx2, transient_key: rkey2}} =
            cctx
            |> ContextConfig.set(:iv, iv)
            |> Cipher.cipher_init()
            |> Cipher.cipher_update(tbe_data)
            |> Cipher.cipher_final()

          # IO.puts("ctx2 : ")
          # IO.inspect(ctx2)

          case ContextConfig.get(ctx2, :iv_length) > 0 do
            true ->
              assert(ContextConfig.get(ctx2, :iv) == nil)

            _ ->
              nil
          end

          # CipherContextBuilder.cipher_context(ctx)
          # |> ContextConfig.set(:session_key, key)
          {:ok, plain} =
            Cipher.cipher_init(ctx, %{password: "p@ssw0rd"})
            |> Cipher.cipher_update(cipher)
            |> Cipher.cipher_final()

          assert(plain == tbe_data)

          {:ok, %{cipher: cipher3, cipher_context: ctx3, transient_key: rkey3}} =
            cctx
            |> ContextConfig.set(:iv, iv)
            |> Cipher.cipher(tbe_data)

          {:ok, plain3} = Cipher.cipher(ctx3, cipher3, %{password: "p@ssw0rd", iv: iv})
          assert(plain3 == plain)

          # Negative #1: no key given
          res = Cipher.cipher_init(ctx)
          # IO.inspect(res)
          assert(res == {:error, :decryption_key_is_required})

          case ContextConfig.get(ctx2, :iv_length) > 0 do
            true ->
              # negative #2: no IV given
              res2 = Cipher.cipher_init(ctx2, %{password: "p@ssw0rd"})
              # IO.inspect(res2)
              assert(res2 == {:error, :decryption_iv_is_required})

            _ ->
              nil
          end
      end
    end
  end

  test "Chunk encrypt and decrypt with cipher context" do
    for c <- CipherContextBuilder.supported_ciphers() do
      IO.puts("Testing cipher : #{c}")

      case CipherContextBuilder.user_key_cipher_context(c, "p@ssw0rd") do
        {:error, reason} ->
          {:error, reason}

        ctx ->
          {:ok, %{cipher: cipher, cipher_context: ctx, transient_key: key}} =
            Cipher.cipher_init(ctx)
            |> Cipher.cipher_update("first batch")
            |> Cipher.cipher_update(" second batch")
            |> Cipher.cipher_update(" third batch")
            |> Cipher.cipher_final()

          # IO.inspect(ctx)

          {:ok, plain} =
            Cipher.cipher_init(ctx, %{password: "p@ssw0rd"})
            |> Cipher.cipher_update(cipher)
            |> Cipher.cipher_final()

          assert(plain == "first batch second batch third batch")
      end
    end
  end
end
