defmodule StrapSoftPrivateKeystore.SoftKeypair do
  alias ExCcrypto.Asymkey.KazKem.KazKemKeypair
  alias ExCcrypto.Asymkey.MlKem.MlKemKeypair
  alias ExCcrypto.Asymkey.SlhDsa.SlhDsaKeypair
  alias ExCcrypto.Asymkey.MlDsa.MlDsaKeypair
  alias ExCcrypto.Asymkey.KazSign.KazSignKeypair
  alias StrapSoftPrivateKeystore.SoftKeypair
  alias ExCcrypto.Asymkey.Ecc.EccKeypair
  use TypedStruct

  typedstruct do
    field(:key_type, any())
    field(:keypair, any())
    field(:add_info, any())
  end

  def new(kp, add_info \\ %{})

  def new(%EccKeypair{} = kp, add_info) do
    %SoftKeypair{
      key_type: :ecc,
      keypair: kp,
      add_info: add_info
    }
  end

  def new(%KazSignKeypair{} = kp, add_info) do
    %SoftKeypair{
      key_type: :kaz_sign,
      keypair: kp,
      add_info: add_info
    }
  end

  def new(%MlDsaKeypair{} = kp, add_info) do
    %SoftKeypair{
      key_type: :ml_dsa,
      keypair: kp,
      add_info: add_info
    }
  end

  def new(%SlhDsaKeypair{} = kp, add_info) do
    %SoftKeypair{
      key_type: :slh_dsa,
      keypair: kp,
      add_info: add_info
    }
  end

  def new(%MlKemKeypair{} = kp, add_info) do
    %SoftKeypair{
      key_type: :ml_kem,
      keypair: kp,
      add_info: add_info
    }
  end

  def new(%KazKemKeypair{} = kp, add_info) do
    %SoftKeypair{
      key_type: :kaz_kem,
      keypair: kp,
      add_info: add_info
    }
  end

  def keypair(%SoftKeypair{} = kp), do: kp.keypair
end

defimpl StrapPrivateKeystore.KeypairManager, for: StrapSoftPrivateKeystore.SoftKeypair do
  alias StrapSoftPrivateKeystore.SoftKeystore
  alias StrapSoftPrivateKeystore.SoftKeypair
  alias StrapPrivateKeystore.KeypairManager
  alias StrapPrivateKeystore.KeypairManager

  def to_keystore(%SoftKeypair{} = kp, auth_token, opts) do
    with {:ok, ksres} <- KeypairManager.to_keystore(SoftKeypair.keypair(kp), auth_token, opts) do
      case ksres.store_type do
        :raw ->
          {:ok,
           %SoftKeystore{
             SoftKeystore.new(ksres.cipher, ksres.cipher_context)
             | certificate: Map.get(kp.add_info, :certificate, nil),
               cert_chain: Map.get(kp.add_info, :cert_chain, nil)
           }}

        :p12 ->
          {:ok, ksres.keystore_envp}
      end
    end
  end

  def set_additional_info(%SoftKeypair{} = kp, key, value, _opts) do
    {:ok, %SoftKeypair{kp | add_info: Map.put(kp.add_info, key, value)}}
  end

  def remove_additional_info(%SoftKeypair{} = kp, key, _opts) do
    {:ok, %SoftKeypair{kp | add_info: Map.delete(kp.add_info, key)}}
  end

  def get_additional_info(%SoftKeypair{} = kp, key, _opts), do: Map.get(kp.add_info, key)

  def public_key(kp, opts), do: KeypairManager.public_key(SoftKeypair.keypair(kp), opts)

  def private_key(kp, opts), do: KeypairManager.private_key(SoftKeypair.keypair(kp), opts)

  def sign_data(kp, data, opts), do: KeypairManager.sign_data(SoftKeypair.keypair(kp), data, opts)

  def verify_data(kp, data, signature, opts),
    do: KeypairManager.verify_data(SoftKeypair.keypair(kp), data, signature, opts)

  def encrypt_data(kp, data, opts),
    do: KeypairManager.encrypt_data(SoftKeypair.keypair(kp), data, opts)

  def decrypt_data(kp, cipher, opts),
    do: KeypairManager.decrypt_data(SoftKeypair.keypair(kp), cipher, opts)

  # no effect in soft keypair 
  def delete_keypair(_kp, _opts), do: :ok

  def open(kp, _opts), do: {:ok, kp}
  def open2(kp, _cb, _opts), do: {:ok, kp}
  def close(kp, _opts), do: {:ok, kp}
end
