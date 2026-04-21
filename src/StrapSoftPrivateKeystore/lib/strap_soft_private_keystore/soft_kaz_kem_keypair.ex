defmodule StrapSoftPrivateKeystore.SoftKazKemKeypair do
end

alias ExCcrypto.Asymkey.KazKem.KazKemKeypair

defimpl StrapPrivateKeystore.KeypairManager, for: KazKemKeypair do
  alias ExCcrypto.Asymkey.KazKem.KazKemKeypair
  alias ExCcrypto.Asymkey.AsymkeyEncryptContextBuilder
  alias ExCcrypto.Asymkey.AsymkeyDecrypt
  alias ExCcrypto.Asymkey.AsymkeyEncrypt
  alias ExCcrypto.Asymkey.Asymkeystore

  def to_keystore(%KazKemKeypair{} = kp, auth_token, opts) do
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

  def public_key(%KazKemKeypair{} = kp, _opts), do: kp.public_key

  def private_key(%KazKemKeypair{} = kp, _opts), do: kp.private_key

  def sign_data(%KazKemKeypair{}, _, _),
    do: {:error, :kaz_kem_not_supporting_signing_operation}

  def verify_data(%KazKemKeypair{}, _, _, _),
    do: {:error, :kaz_kem_not_supporting_digital_signature_verifying_operation}

  def encrypt_data(%KazKemKeypair{} = kp, data, %{data_feeder: feeder}) when not is_nil(feeder) do
    esess =
      AsymkeyEncryptContextBuilder.encrypt_context(kp.public_key)
      |> AsymkeyEncrypt.encrypt_init()
      |> AsymkeyEncrypt.encrypt_update(data)

    eusess = update_encrypt_data(esess, feeder, feeder.(:read_data))

    AsymkeyEncrypt.encrypt_final(eusess)
  end

  def encrypt_data(%KazKemKeypair{} = kp, data, _opts) do
    AsymkeyEncryptContextBuilder.encrypt_context(kp.public_key)
    |> AsymkeyEncrypt.encrypt_init()
    |> AsymkeyEncrypt.encrypt_update(data)
    |> AsymkeyEncrypt.encrypt_final()
  end

  def decrypt_data(%KazKemKeypair{} = kp, cipher, %{data_feeder: feeder})
      when not is_nil(feeder) do
    with {:ok, ctx} <-
           AsymkeyDecrypt.decrypt_init(cipher, kp.public_key, kp.private_key) do
      dsess = AsymkeyDecrypt.decrypt_update(ctx, cipher.cipher)

      dusess = update_decrypt_data(dsess, feeder, feeder.(:read_data))

      AsymkeyDecrypt.decrypt_final(dusess)
    end
  end

  def decrypt_data(%KazKemKeypair{} = kp, cipher, _opts) do
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
