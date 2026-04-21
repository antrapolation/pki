defmodule SlhDsaAsymkeyTest do
  alias ExCcrypto.Asymkey.AsymkeyVerify
  alias ExCcrypto.Asymkey.AsymkeySign
  alias ApJavaCrypto.SlhDsa.SlhDsaContext
  alias ExCcrypto.Asymkey.AsymkeystoreLoader
  alias ExCcrypto.Asymkey.Asymkeystore
  alias ExCcrypto.Asymkey
  alias ExCcrypto.ContextConfig
  alias ApJavaCrypto.SlhDsa.SlhDsaKeypair
  use ExUnit.Case

  test "SLH-DSA Key generation and encoding/decoding via protocol" do
    for c <-
          %SlhDsaKeypair{}
          |> ContextConfig.get(:supported_variant) do
      {:ok, kp} =
        %SlhDsaKeypair{}
        |> ContextConfig.set(:variant, c)
        |> Asymkey.generate()

      IO.inspect(kp)

      {:ok, enc_ks} = Asymkeystore.to_keystore(kp, %{password: "p@ssw0rd"})
      IO.puts("To Keystore : #{inspect(enc_ks)}")

      {:ok, rks} = AsymkeystoreLoader.from_keystore(enc_ks, %{password: "p@ssw0rd"})
      IO.puts("from keystore : #{inspect(rks)}")
      assert rks == kp

      assert {:error, :password_incorrect} =
               AsymkeystoreLoader.from_keystore(enc_ks, %{password: "p@ssw0rd=="})
    end
  end

  test "SLH-DSA sign and verify data using raw keypair" do
    for c <-
          %SlhDsaKeypair{}
          |> ContextConfig.get(:supported_variant) do
      IO.puts("ML-DSA sign verify using variant : #{c}")

      {:ok, kp} =
        %SlhDsaKeypair{}
        |> ContextConfig.set(:variant, c)
        |> Asymkey.generate()

      tbs_data = "this is test input for signing for SLH-DSA variant #{c}"

      # {:ok, signRes} =
      with ctx when not is_tuple(ctx) <-
             %SlhDsaContext{}
             |> ContextConfig.set(:private_key, kp.private_key) do
        {:ok, signRes} =
          ctx
          |> AsymkeySign.sign_init()
          |> AsymkeySign.sign_update(tbs_data)
          |> AsymkeySign.sign_final()

        IO.inspect(signRes)

        {:ok, verRes} =
          AsymkeyVerify.verify_init(signRes, %{verification_key: kp.public_key})
          |> AsymkeyVerify.verify_update(tbs_data)
          |> AsymkeyVerify.verify_final(ContextConfig.get(signRes, :signature))

        IO.inspect(verRes)
        assert(verRes.verification_result == true)

        {:ok, verRes2} =
          AsymkeyVerify.verify_init(signRes, %{verification_key: kp.public_key})
          |> AsymkeyVerify.verify_update("#{tbs_data}.")
          |> AsymkeyVerify.verify_final(ContextConfig.get(signRes, :signature))

        IO.inspect(verRes2)
        assert(verRes2.verification_result == false)

        {:ok, signRes2} =
          %SlhDsaContext{private_key: kp.private_key}
          |> AsymkeySign.sign_init()
          |> AsymkeySign.sign_update(tbs_data)
          |> AsymkeySign.sign_final()

        {:ok, verRes3} =
          AsymkeyVerify.verify_init(signRes2, %{verification_key: kp.public_key})
          |> AsymkeyVerify.verify_update(tbs_data)
          |> AsymkeyVerify.verify_final(ContextConfig.get(signRes2, :signature))

        IO.inspect(verRes3)
        assert(verRes3.verification_result == true)
      else
        err -> IO.inspect(err)
      end
    end
  end

  # test "ECC attached sign and verify data using raw keypair" do
  #  for c <-
  #        AsymkeyContextBuilder.generator_context(:ecc)
  #        |> ContextConfig.get(:supported_curves) do
  #    IO.puts("Sign verify using curve : #{c}")

  #    {:ok, kp} =
  #      AsymkeyContextBuilder.generator_context(:ecc)
  #      |> ContextConfig.set(:curve, c)
  #      |> Asymkey.generate()

  #    tbs_data = "this is test input for attaached signing using ECC curve #{c}"

  #    # {:ok, signRes} =
  #    with ctx when not is_tuple(ctx) <-
  #           AsymkeySignContextBuilder.sign_context(:ecc)
  #           |> ContextConfig.set(:private_key, kp.private_key) do
  #      {:ok, signRes} =
  #        ctx
  #        |> ContextConfig.set(:enable_attached_mode, true)
  #        |> AsymkeySign.sign_init()
  #        |> AsymkeySign.sign_update(tbs_data)
  #        |> AsymkeySign.sign_final()

  #      IO.inspect(signRes)

  #      {:ok, verRes} =
  #        AsymkeyVerify.verify_init(signRes, %{verification_key: kp.public_key})
  #        |> AsymkeyVerify.verify_update()
  #      #        |> AsymkeyVerify.verify_final()

  #      IO.inspect(verRes)
  #      assert(verRes.verification_result == true)
  #      assert(verRes.attached_data == tbs_data)

  #      {:ok, verRes2} =
  #        AsymkeyVerify.verify_init(signRes, %{verification_key: kp.public_key})
  #        |> AsymkeyVerify.verify_update("#{tbs_data}.")
  #        |> AsymkeyVerify.verify_final()

  #      IO.inspect(verRes2)
  #      # this will be true because the data never referred since it is attached signed
  #      assert(verRes2.verification_result == true)
  #      assert(verRes2.attached_data == tbs_data)

  #      {:ok, signRes2} =
  #        AsymkeySignContextBuilder.sign_context(kp.private_key)
  #        |> ContextConfig.set(:enable_attached_mode, true)
  #        |> ContextConfig.set(:enable_attached_data_compression, true)
  #        |> AsymkeySign.sign_init()
  #        |> AsymkeySign.sign_update(tbs_data)
  #        |> AsymkeySign.sign_final()

  #      IO.puts("sign with data compression turned on")
  #      IO.inspect(signRes2)

  #      {:ok, verRes3} =
  #        AsymkeyVerify.verify_init(signRes2, %{verification_key: kp.public_key})
  #        |> AsymkeyVerify.verify_update()
  #        |> AsymkeyVerify.verify_final()

  #      IO.puts("verify with data compression turned on")
  #      IO.inspect(verRes3)
  #      assert(verRes3.verification_result == true)
  #      assert(verRes3.attached_data == tbs_data)
  #    else
  #      err -> IO.inspect(err)
  #    end
  #  end
  # end

  # KAZ-KEM / KAZ-KA test case
  # test "ECC encrypt and decrypt data using raw keypair" do
  #  for c <-
  #        AsymkeyContextBuilder.generator_context(:ecc)
  #        |> ContextConfig.get(:supported_curves) do
  #    IO.puts("Using ECC curve #{c} for encrypt & decrypt test")

  #    {:ok, kp1} =
  #      AsymkeyContextBuilder.generator_context(:ecc)
  #      |> ContextConfig.set(:curve, c)
  #      |> Asymkey.generate()

  #    {:ok, kp2} =
  #      AsymkeyContextBuilder.generator_context(:ecc)
  #      |> ContextConfig.set(:curve, c)
  #      |> Asymkey.generate()

  #    {:ok, kp3} =
  #      AsymkeyContextBuilder.generator_context(:ecc)
  #      |> ContextConfig.set(:curve, c)
  #      |> Asymkey.generate()

  #    with ctx when not is_tuple(ctx) <-
  #           AsymkeyEncryptContextBuilder.encrypt_context(:ecc)
  #           |> ContextConfig.set(:add_encryption_key, kp1.public_key) do
  #      sensitive_data = "this is sensitive data for enc dec operation"

  #      {:ok, enc} =
  #        ctx
  #        # AsymkeyEncryptContextBuilder.encrypt_context(:ecc)
  #        # |> ContextConfig.set(:add_encryption_key, kp1.public_key)
  #        |> ContextConfig.set(:add_encryption_key, kp2.public_key)
  #        |> AsymkeyEncrypt.encrypt_init()
  #        |> AsymkeyEncrypt.encrypt_update(sensitive_data)
  #        |> AsymkeyEncrypt.encrypt_final()

  #      IO.puts("Encrypted : ")
  #      IO.inspect(enc)

  #      res =
  #        with {:ok, ctx} <- AsymkeyDecrypt.decrypt_init(enc, kp1.public_key, kp1.private_key) do
  #          AsymkeyDecrypt.decrypt_update(ctx, enc.cipher)
  #          |> AsymkeyDecrypt.decrypt_final()
  #        end

  #      IO.puts("decrypted : #{inspect(res)}")
  #      assert(res == sensitive_data)

  #      res2 =
  #        with {:ok, ctx} <- AsymkeyDecrypt.decrypt_init(enc, kp2.public_key, kp2.private_key) do
  #          AsymkeyDecrypt.decrypt_update(ctx, enc.cipher)
  #          |> AsymkeyDecrypt.decrypt_final()
  #        end

  #      IO.puts("decrypted : #{inspect(res2)}")
  #      assert(res2 == sensitive_data)

  #      res3 =
  #        AsymkeyDecrypt.decrypt(enc, kp1.public_key, kp1.private_key, enc.cipher)

  #      IO.puts("decrypted : #{inspect(res3)}")
  #      assert(res3 == sensitive_data)

  #      erres =
  #        with {:ok, ctx} <- AsymkeyDecrypt.decrypt_init(enc, kp1.public_key, kp2.private_key) do
  #          AsymkeyDecrypt.decrypt_update(ctx, enc.cipher)
  #          |> AsymkeyDecrypt.decrypt_final()
  #        end

  #      IO.inspect(erres)
  #      assert(erres == {:error, :recipient_decryption_failed})

  #      erres2 =
  #        with {:ok, ctx} <- AsymkeyDecrypt.decrypt_init(enc, kp3.public_key, kp3.private_key) do
  #          AsymkeyDecrypt.decrypt_update(ctx, enc.cipher)
  #          |> AsymkeyDecrypt.decrypt_final()
  #        end

  #      IO.inspect(erres2)
  #      assert(erres2 == {:error, :not_a_recipient})

  #      erres3 =
  #        with {:ok, ctx} <- AsymkeyDecrypt.decrypt_init(enc, kp2.public_key, kp2.private_key) do
  #          AsymkeyDecrypt.decrypt_update(ctx, :crypto.strong_rand_bytes(57))
  #          |> AsymkeyDecrypt.decrypt_final()
  #        end

  #      IO.inspect(erres3)
  #    else
  #      err -> IO.puts(inspect(err))
  #    end
  #  end
  # end
end
