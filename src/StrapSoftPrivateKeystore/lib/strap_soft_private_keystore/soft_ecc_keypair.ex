defmodule StrapSoftPrivateKeystore.SoftEccKeypair do
end

defimpl StrapPrivateKeystore.KeypairManager, for: ExCcrypto.Asymkey.Ecc.EccKeypair do
  alias ExCcrypto.Keystore
  alias ExCcrypto.Asymkey.KeyEncoding
  alias ExCcrypto.Asymkey.ExternalSigner
  alias ExCcrypto.Asymkey.AsymkeyDecrypt
  alias ExCcrypto.Asymkey.AsymkeyEncrypt
  alias ExCcrypto.Asymkey.AsymkeyEncryptContextBuilder
  alias ExCcrypto.Asymkey.AsymkeyVerify
  alias ExCcrypto.Asymkey.AsymkeySign
  alias ExCcrypto.ContextConfig
  alias ExCcrypto.Asymkey.AsymkeySignContextBuilder
  alias ExCcrypto.Asymkey.Asymkeystore
  alias ExCcrypto.Asymkey.Ecc.EccKeypair

  def to_keystore(_kp, _auth_token, %{format: :p12, cert: cert})
      when is_nil(cert),
      do: {:error, :to_p12_keystore_required_certificate_to_be_present}

  def to_keystore(%EccKeypair{} = kp, auth_token, %{format: :p12} = opts) do
    cert = Map.get(opts, :cert)
    chain = Map.get(opts, :cert_chain, [])

    {:ok,
     %{store_type: :p12, keystore_envp: Keystore.to_pkcs12_keystore(kp, cert, chain, auth_token)}}
  end

  def to_keystore(%EccKeypair{} = kp, auth_token, opts) do
    with {:ok, %{cipher: kscipher, cipher_context: ksctx}} <-
           Asymkeystore.to_keystore(
             kp,
             Map.put_new(opts, :password, auth_token) |> Map.put_new(:return_raw, true)
           ) do
      {:ok, %{store_type: :raw, cipher: kscipher, cipher_context: ksctx}}
    end
  end

  def set_additional_info(_ks, _key, _value, _opts), do: :ok

  def remove_additional_info(_ks, _key, _opts), do: :ok

  def get_additional_info(_ks, _key, _opts), do: :ok

  def public_key(%EccKeypair{} = kp, _opts), do: kp.public_key

  def private_key(%EccKeypair{} = kp, :exccrypto_external_signer) do
    %ExternalSigner{}
    |> ExternalSigner.set_callback(fn tbs, hash, _opts ->
      :public_key.sign(tbs, hash, KeyEncoding.to_native!(kp.private_key))
    end)
    |> ExternalSigner.set_key_algo(:ecdsa)
    |> ExternalSigner.set_public_key(KeyEncoding.to_native!(kp.public_key))
  end

  def private_key(%EccKeypair{} = kp, _opts), do: kp.private_key

  def sign_data(%EccKeypair{} = kp, data, %{data_feeder: feeder})
      when not is_nil(feeder) do
    ssess =
      AsymkeySignContextBuilder.sign_context(:ecc)
      |> ContextConfig.set(:private_key, kp.private_key)
      |> AsymkeySign.sign_init()
      |> AsymkeySign.sign_update(data)

    fsess = update_sign_data(ssess, feeder, feeder.(:read_data))

    AsymkeySign.sign_final(fsess)
  end

  def sign_data(%EccKeypair{} = kp, data, _opts) do
    AsymkeySignContextBuilder.sign_context(:ecc)
    |> ContextConfig.set(:private_key, kp.private_key)
    |> AsymkeySign.sign_init()
    |> AsymkeySign.sign_update(data)
    |> AsymkeySign.sign_final()
  end

  def verify_data(%EccKeypair{} = kp, data, signature, %{data_feeder: feeder})
      when not is_nil(feeder) do
    vsess =
      AsymkeyVerify.verify_init(signature, %{
        verification_key: kp.public_key
      })
      |> AsymkeyVerify.verify_update(data)

    vusess = update_verify_data(vsess, feeder, feeder.(:read_data))

    AsymkeyVerify.verify_final(vusess, ContextConfig.get(signature, :signature))
  end

  def verify_data(%EccKeypair{} = kp, data, signature, _opts) do
    AsymkeyVerify.verify_init(signature, %{
      verification_key: kp.public_key
    })
    |> AsymkeyVerify.verify_update(data)
    |> AsymkeyVerify.verify_final(ContextConfig.get(signature, :signature))
  end

  def encrypt_data(%EccKeypair{} = kp, data, %{data_feeder: feeder}) when not is_nil(feeder) do
    esess =
      AsymkeyEncryptContextBuilder.encrypt_context(kp.public_key)
      |> AsymkeyEncrypt.encrypt_init()
      |> AsymkeyEncrypt.encrypt_update(data)

    eusess = update_encrypt_data(esess, feeder, feeder.(:read_data))

    AsymkeyEncrypt.encrypt_final(eusess)
  end

  def encrypt_data(%EccKeypair{} = kp, data, _opts) do
    AsymkeyEncryptContextBuilder.encrypt_context(kp.public_key)
    |> AsymkeyEncrypt.encrypt_init()
    |> AsymkeyEncrypt.encrypt_update(data)
    |> AsymkeyEncrypt.encrypt_final()
  end

  def decrypt_data(%EccKeypair{} = kp, cipher, %{data_feeder: feeder}) when not is_nil(feeder) do
    with {:ok, ctx} <-
           AsymkeyDecrypt.decrypt_init(cipher, kp.public_key, kp.private_key) do
      dsess = AsymkeyDecrypt.decrypt_update(ctx, cipher.cipher)

      dusess = update_decrypt_data(dsess, feeder, feeder.(:read_data))

      AsymkeyDecrypt.decrypt_final(dusess)
    end
  end

  def decrypt_data(%EccKeypair{} = kp, cipher, _opts) do
    with {:ok, ctx} <-
           AsymkeyDecrypt.decrypt_init(cipher, kp.public_key, kp.private_key) do
      AsymkeyDecrypt.decrypt_update(ctx, cipher.cipher)
      |> AsymkeyDecrypt.decrypt_final()
    end
  end

  # no effect in soft keypair 
  def delete_keypair(_kp, _opts), do: :ok

  def open(kp, _opts), do: {:ok, kp}
  def open2(kp, _cb, _opts), do: {:ok, kp}
  def close(kp, _opts), do: {:ok, kp}

  # 
  # Private functions
  #
  defp update_sign_data(sess, _feeder, []), do: sess
  defp update_sign_data(sess, _feeder, nil), do: sess

  defp update_sign_data(sess, feeder, data) do
    AsymkeySign.sign_update(sess, data)
    update_sign_data(sess, feeder, feeder.(:read_data))
  end

  defp update_verify_data(sess, _feeder, []), do: sess
  defp update_verify_data(sess, _feeder, nil), do: sess

  defp update_verify_data(sess, feeder, data) do
    AsymkeyVerify.verify_update(sess, data)
    update_verify_data(sess, feeder, feeder.(:read_data))
  end

  defp update_encrypt_data(sess, _feeder, []), do: sess
  defp update_encrypt_data(sess, _feeder, nil), do: sess

  defp update_encrypt_data(sess, feeder, data) do
    AsymkeyEncrypt.encrypt_update(sess, data)
    update_encrypt_data(sess, feeder, feeder.(:read_data))
  end

  defp update_decrypt_data(sess, _feeder, []), do: sess
  defp update_decrypt_data(sess, _feeder, nil), do: sess

  defp update_decrypt_data(sess, feeder, data) do
    AsymkeyDecrypt.decrypt_update(sess, data)
    update_decrypt_data(sess, feeder, feeder.(:read_data))
  end
end
