defmodule StrapSoftPrivateKeystore.SoftKeystore do
  alias StrapSoftPrivateKeystore.SoftKeystore
  use TypedStruct

  typedstruct do
    field(:encrypted_keystore, any())
    field(:encrypted_keystore_context, any())
    field(:certificate, any())
    field(:cert_chain, any())
  end

  def new(cipher, context) do
    %SoftKeystore{encrypted_keystore: cipher, encrypted_keystore_context: context}
  end
end

defimpl StrapPrivateKeystore.KeystoreManager, for: StrapSoftPrivateKeystore.SoftKeystore do
  alias StrapSoftPrivateKeystore.SoftKeypair
  alias StrapPrivateKeystore.KeypairManager
  alias StrapPrivateKeystore.KeystoreManager
  alias ExCcrypto.Asymkey.AsymkeystoreLoader
  alias StrapSoftPrivateKeystore.SoftKeystore

  def keystore_to_keypair(%SoftKeystore{} = ks, auth_token, _opts) do
    with {:ok, kp} <-
           AsymkeystoreLoader.from_keystore(
             %{cipher: ks.encrypted_keystore, cipher_context: ks.encrypted_keystore_context},
             %{password: auth_token}
           ) do
      skp = SoftKeypair.new(kp)

      {:ok,
       %SoftKeypair{
         skp
         | add_info:
             Map.put(skp.add_info, :certificate, ks.certificate)
             |> Map.put(:cert_chain, ks.cert_chain)
       }}
    end
  end

  def update_keystore_auth_token(%SoftKeystore{} = ks, existing, new, _opts) do
    with {:ok, kp} <- KeystoreManager.keystore_to_keypair(ks, existing),
         {:ok, nks} <- KeypairManager.to_keystore(kp, new) do
      {:ok, nks}
    end
  end
end
