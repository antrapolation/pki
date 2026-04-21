defmodule CipherTest do
  alias ExCcrypto.ContextConfig
  alias ExCcrypto.Cipher.CipherContextEncoder
  alias ExCcrypto.Cipher.CipherContextBuilder
  alias ExCcrypto.Cipher
  use ExUnit.Case

  test "Encrypt and decrypt with selected AEAD cipher context" do
    tbe_data = "this is sensitive data to encrypt for selected AEAD cipher context"

    case CipherContextBuilder.cipher_context(:aes_256_gcm) do
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
          Cipher.cipher_init(ectx, %{session_key: key})
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

  test "Encrypt and decrypt with selected block cipher context" do
    tbe_data = "this is sensitive data to encrypt for selected block cipher context"

    case CipherContextBuilder.cipher_context(:aes_256_cbc) do
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
          Cipher.cipher_init(ectx, %{session_key: key})
          |> Cipher.cipher_update(cipher)
          |> Cipher.cipher_final()

        IO.puts("block cipher decrypted : #{plain}")
        assert(plain == tbe_data)

        {:ok, %{cipher: cipher2, cipher_context: ctx2, transient_key: key2}} =
          Cipher.cipher(ctx, tbe_data)

        {:ok, plain2} = Cipher.cipher(ctx2, cipher2, %{session_key: key2})
        assert(plain2 == plain)
    end
  end

  test "Encrypt and decrypt with all supported cipher context" do
    tbe_data = "this is sensitive data to encrypt for all supported cipher context"

    for c <- CipherContextBuilder.supported_ciphers() do
      # for c <- [:aes_128_gcm] do
      IO.puts("Testing cipher : #{c}")

      case CipherContextBuilder.cipher_context(c) do
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
            Cipher.cipher_init(ectx, %{session_key: key})
            |> Cipher.cipher_update(cipher)
            |> Cipher.cipher_final()

          assert(plain == tbe_data)

          {:ok, %{cipher: cipher2, cipher_context: ctx2, transient_key: key2}} =
            Cipher.cipher(ctx, tbe_data)

          {:ok, plain2} = Cipher.cipher(ctx2, cipher2, %{session_key: key2})
          assert(plain2 == plain)
      end
    end
  end

  test "Encrypt and decrypt with all supported Cipher Context with external key and iv (negative test)" do
    tbe_data = "this is sensitive data for encryption"

    for c <- CipherContextBuilder.supported_ciphers() do
      IO.puts("Testing cipher : #{c}")

      res =
        case CipherContextBuilder.cipher_context(c) do
          {:error, reason} ->
            {:error, reason}

          cctx ->
            bkey = :crypto.strong_rand_bytes(ContextConfig.get(cctx, :key_byte_size) - 1)

            assert(
              ContextConfig.set(cctx, :session_key, bkey) ==
                {:error,
                 {:required_key_length_not_match, byte_size(bkey),
                  ContextConfig.get(cctx, :key_byte_size)}}
            )

            cond do
              ContextConfig.get(cctx, :iv_length) > 0 ->
                biv = :crypto.strong_rand_bytes(ContextConfig.get(cctx, :iv_length) - 1)

                assert(
                  ContextConfig.set(cctx, :iv, biv) ==
                    {:error,
                     {:given_iv_does_not_meet_required_length, byte_size(biv),
                      ContextConfig.get(cctx, :iv_length)}}
                )

              true ->
                true
            end
        end
    end
  end

  test "Encrypt and decrypt with all supported Cipher Context with external key and iv" do
    tbe_data = "this is sensitive data for encryption"

    for c <- CipherContextBuilder.supported_ciphers() do
      IO.puts("Testing cipher : #{c}")

      case CipherContextBuilder.cipher_context(c) do
        {:error, reason} ->
          {:error, reason}

        cctx ->
          key = :crypto.strong_rand_bytes(ContextConfig.get(cctx, :key_byte_size))
          iv = :crypto.strong_rand_bytes(ContextConfig.get(cctx, :iv_length))

          {:ok, %{cipher: cipher, cipher_context: ctx, transient_key: rkey}} =
            cctx
            |> ContextConfig.set(:session_key, key)
            |> Cipher.cipher_init()
            |> Cipher.cipher_update(tbe_data)
            |> Cipher.cipher_final()

          assert(rkey == key)
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
            |> ContextConfig.set(:session_key, key)
            |> ContextConfig.set(:iv, iv)
            |> Cipher.cipher_init()
            |> Cipher.cipher_update(tbe_data)
            |> Cipher.cipher_final()

          assert(rkey2 == key)
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
            Cipher.cipher_init(ctx, %{session_key: key})
            |> Cipher.cipher_update(cipher)
            |> Cipher.cipher_final()

          assert(plain == tbe_data)

          {:ok, %{cipher: cipher3, cipher_context: ctx3, transient_key: rkey3}} =
            cctx
            |> ContextConfig.set(:session_key, key)
            |> ContextConfig.set(:iv, iv)
            |> Cipher.cipher(tbe_data)

          {:ok, plain3} = Cipher.cipher(ctx3, cipher3, %{session_key: key, iv: iv})
          assert(plain3 == plain)

          # Negative #1: no key given
          res = Cipher.cipher_init(ctx)
          # IO.inspect(res)
          assert(res == {:error, :decryption_key_is_required})

          case ContextConfig.get(ctx2, :iv_length) > 0 do
            true ->
              # negative #2: no IV given
              res2 = Cipher.cipher_init(ctx2, %{session_key: key})
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

      case CipherContextBuilder.cipher_context(c) do
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
            Cipher.cipher_init(ctx, %{session_key: key})
            |> Cipher.cipher_update(cipher)
            |> Cipher.cipher_final()

          assert(plain == "first batch second batch third batch")
      end
    end
  end

  test "Block cipher decryption requires key and iv when applicable" do
    ctx = CipherContextBuilder.cipher_context(:aes_256_cbc)

    dec_ctx =
      ctx
      |> ContextConfig.set(:cipher_ops, :decrypt)

    assert Cipher.cipher_init(dec_ctx) == {:error, :decryption_key_is_required}

    key = :crypto.strong_rand_bytes(ContextConfig.get(dec_ctx, :key_byte_size))

    dec_ctx_with_key =
      dec_ctx
      |> ContextConfig.set(:session_key, key)

    if ContextConfig.get(dec_ctx_with_key, :iv_length) > 0 do
      assert Cipher.cipher_init(dec_ctx_with_key) == {:error, :decryption_iv_is_required}
    end
  end
end
