defmodule MlKemAsymkeyTest do
  alias ExCcrypto.Asymkey.AsymkeyDecrypt
  alias ExCcrypto.Asymkey.AsymkeyEncrypt
  alias ApJavaCrypto.MlKem.MlKemContext
  alias ExCcrypto.Asymkey.AsymkeystoreLoader
  alias ExCcrypto.Asymkey.Asymkeystore
  alias ExCcrypto.Asymkey
  alias ExCcrypto.ContextConfig
  alias ApJavaCrypto.MlKem.MlKemKeypair

  use ExUnit.Case

  test "ML-KEM Key generation and encoding/decoding via protocol" do
    Enum.each(ContextConfig.get(%MlKemKeypair{}, :supported_variant), fn algo ->
      {:ok, kp} =
        %MlKemKeypair{}
        |> ContextConfig.set(:variant, algo)
        |> Asymkey.generate()

      IO.inspect(kp)

      {:ok, enc_ks} = Asymkeystore.to_keystore(kp, %{password: "p@ssw0rd"})
      IO.inspect(enc_ks)

      {:ok, rks} = AsymkeystoreLoader.from_keystore(enc_ks, %{password: "p@ssw0rd"})
      IO.inspect(rks)
      assert rks == kp

      assert {:error, :password_incorrect} =
               AsymkeystoreLoader.from_keystore(enc_ks, %{password: "p@ssw0rd=="})

      #      end
    end)
  end

  test "ML-KEM encrypt and decrypt data using raw keypair" do
    for c <-
          %MlKemKeypair{}
          |> ContextConfig.get(:supported_variant) do
      IO.puts("Using ML-KEM #{c} for encrypt & decrypt test")

      {:ok, kp1} =
        %MlKemKeypair{}
        |> ContextConfig.set(:variant, c)
        |> Asymkey.generate()

      {:ok, kp2} =
        %MlKemKeypair{}
        |> ContextConfig.set(:variant, c)
        |> Asymkey.generate()

      {:ok, kp3} =
        %MlKemKeypair{}
        |> ContextConfig.set(:variant, c)
        |> Asymkey.generate()

      # 
      # tuple means error
      #
      with ctx when not is_tuple(ctx) <-
             %MlKemContext{}
             |> ContextConfig.set(:add_encryption_key, kp1.public_key) do
        sensitive_data = "this is sensitive data for enc dec operation"

        {:ok, enc} =
          ctx
          # AsymkeyEncryptContextBuilder.encrypt_context(:ecc)
          # |> ContextConfig.set(:add_encryption_key, kp1.public_key)
          |> ContextConfig.set(:add_encryption_key, kp2.public_key)
          |> AsymkeyEncrypt.encrypt_init()
          |> AsymkeyEncrypt.encrypt_update(sensitive_data)
          |> AsymkeyEncrypt.encrypt_final()

        IO.puts("Encrypted : ")
        IO.inspect(enc)

        res =
          with {:ok, ctx} <- AsymkeyDecrypt.decrypt_init(enc, kp1.public_key, kp1.private_key) do
            AsymkeyDecrypt.decrypt_update(ctx, enc.cipher)
            |> AsymkeyDecrypt.decrypt_final()
          end

        IO.puts("decrypted : #{inspect(res)}")
        assert(res == sensitive_data)

        res2 =
          with {:ok, ctx} <- AsymkeyDecrypt.decrypt_init(enc, kp2.public_key, kp2.private_key) do
            AsymkeyDecrypt.decrypt_update(ctx, enc.cipher)
            |> AsymkeyDecrypt.decrypt_final()
          end

        IO.puts("decrypted : #{inspect(res2)}")
        assert(res2 == sensitive_data)

        res3 =
          AsymkeyDecrypt.decrypt(enc, kp1.public_key, kp1.private_key, enc.cipher)

        IO.puts("decrypted : #{inspect(res3)}")
        assert(res3 == sensitive_data)

        erres =
          with {:ok, ctx} <- AsymkeyDecrypt.decrypt_init(enc, kp1.public_key, kp2.private_key) do
            AsymkeyDecrypt.decrypt_update(ctx, enc.cipher)
            |> AsymkeyDecrypt.decrypt_final()
          end

        IO.inspect(erres)
        assert(erres == {:error, :recipient_decryption_failed})

        erres2 =
          with {:ok, ctx} <- AsymkeyDecrypt.decrypt_init(enc, kp3.public_key, kp3.private_key) do
            AsymkeyDecrypt.decrypt_update(ctx, enc.cipher)
            |> AsymkeyDecrypt.decrypt_final()
          end

        IO.inspect(erres2)
        assert(erres2 == {:error, :not_a_recipient})

        erres3 =
          with {:ok, ctx} <- AsymkeyDecrypt.decrypt_init(enc, kp2.public_key, kp2.private_key) do
            AsymkeyDecrypt.decrypt_update(ctx, :crypto.strong_rand_bytes(57))
            |> AsymkeyDecrypt.decrypt_final()
          end

        IO.inspect(erres3)
      else
        err -> IO.puts(inspect(err))
      end
    end
  end
end
