defmodule KazSignAsymkeyTest do
  alias ExCcrypto.Asymkey.AsymkeyVerify
  alias ExCcrypto.Asymkey.AsymkeySign
  alias ApJavaCrypto.KazSign.KazSignContext
  alias ApJavaCrypto.KazSign.KazSignKeypair
  alias ExCcrypto.Asymkey.AsymkeystoreLoader
  alias ExCcrypto.Asymkey.Asymkeystore
  alias ExCcrypto.ContextConfig
  alias ExCcrypto.Asymkey

  use ExUnit.Case

  test "KAZ-SIGN Key generation and encoding/decoding via protocol" do
    for c <-
          %KazSignKeypair{}
          |> ContextConfig.get(:supported_variant) do
      {:ok, kp} =
        %KazSignKeypair{}
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

  test "KAZ-SIGN sign and verify data using raw keypair" do
    for c <-
          %KazSignKeypair{}
          |> ContextConfig.get(:supported_variant) do
      IO.puts("Sign verify using variant : #{c}")

      {:ok, kp} =
        %KazSignKeypair{}
        |> ContextConfig.set(:variant, c)
        |> Asymkey.generate()

      tbs_data = "this is test input for signing for KAZ_SIGN variant #{c}"

      # {:ok, signRes} =
      with ctx when not is_tuple(ctx) <-
             %KazSignContext{}
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
          %KazSignContext{}
          |> ContextConfig.set(:private_key, kp.private_key)
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
end
