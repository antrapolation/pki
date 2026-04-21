defmodule StrapSoftPrivateKeystore.SoftMlDsaKeypair do
end

alias ExCcrypto.Asymkey.MlDsa.MlDsaKeypair

defimpl StrapPrivateKeystore.KeypairManager, for: MlDsaKeypair do
  alias ExCcrypto.Asymkey.MlDsa.MlDsaKeypair
  alias ExCcrypto.Asymkey.AsymkeyVerify
  alias ExCcrypto.Asymkey.AsymkeySign
  alias ExCcrypto.ContextConfig
  alias ExCcrypto.Asymkey.AsymkeySignContextBuilder
  alias ExCcrypto.Asymkey.Asymkeystore

  def to_keystore(%MlDsaKeypair{} = kp, auth_token, opts) do
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

  def public_key(%MlDsaKeypair{} = kp, _opts), do: kp.public_key

  # def private_key(%MlDsaKeypair{} = kp, :exccrypto_external_signer) do
  #  %ExternalSigner{}
  #  |> ExternalSigner.set_callback(fn tbs, hash, _opts ->
  #    :public_key.sign(tbs, hash, KeyEncoding.to_native!(kp.private_key))
  #  end)
  #  |> ExternalSigner.set_key_algo(:ecdsa)
  #  |> ExternalSigner.set_public_key(KeyEncoding.to_native!(kp.public_key))
  # end

  def private_key(%MlDsaKeypair{} = kp, _opts), do: kp.private_key

  def sign_data(%MlDsaKeypair{} = kp, data, %{data_feeder: feeder})
      when not is_nil(feeder) do
    ssess =
      AsymkeySignContextBuilder.sign_context(:ml_dsa)
      |> ContextConfig.set(:private_key, kp.private_key)
      |> AsymkeySign.sign_init()
      |> AsymkeySign.sign_update(data)

    fsess = update_sign_data(ssess, feeder, feeder.(:read_data))

    AsymkeySign.sign_final(fsess)
  end

  def sign_data(%MlDsaKeypair{} = kp, data, _opts) do
    AsymkeySignContextBuilder.sign_context(:ml_dsa)
    |> ContextConfig.set(:private_key, kp.private_key)
    |> AsymkeySign.sign_init()
    |> AsymkeySign.sign_update(data)
    |> AsymkeySign.sign_final()
  end

  def verify_data(%MlDsaKeypair{} = kp, data, signature, %{data_feeder: feeder})
      when not is_nil(feeder) do
    vsess =
      AsymkeyVerify.verify_init(signature, %{
        verification_key: kp.public_key
      })
      |> AsymkeyVerify.verify_update(data)

    vusess = update_verify_data(vsess, feeder, feeder.(:read_data))

    AsymkeyVerify.verify_final(vusess, ContextConfig.get(signature, :signature))
  end

  def verify_data(%MlDsaKeypair{} = kp, data, signature, _opts) do
    AsymkeyVerify.verify_init(signature, %{
      verification_key: kp.public_key
    })
    |> AsymkeyVerify.verify_update(data)
    |> AsymkeyVerify.verify_final(ContextConfig.get(signature, :signature))
  end

  def encrypt_data(%MlDsaKeypair{}, _data, _opts),
    do: {:error, :ml_dsa_not_supporting_encrypt_operation}

  def decrypt_data(%MlDsaKeypair{}, _cipher, _opts),
    do: {:error, :ml_dsa_not_supporting_decrypt_operation}

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

  # defp update_encrypt_data(sess, _feeder, []), do: sess
  # defp update_encrypt_data(sess, _feeder, nil), do: sess

  # defp update_encrypt_data(sess, feeder, data) do
  #  AsymkeyEncrypt.encrypt_update(sess, data)
  #  update_encrypt_data(sess, feeder, feeder.(:read_data))
  # end

  # defp update_decrypt_data(sess, _feeder, []), do: sess
  # defp update_decrypt_data(sess, _feeder, nil), do: sess

  # defp update_decrypt_data(sess, feeder, data) do
  #  AsymkeyDecrypt.decrypt_update(sess, data)
  #  update_decrypt_data(sess, feeder, feeder.(:read_data))
  # end
end
