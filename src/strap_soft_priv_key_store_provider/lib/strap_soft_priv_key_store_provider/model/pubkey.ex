defmodule StrapSoftPrivKeyStoreProvider.Model.Pubkey do
  use TypedStruct

  typedstruct do
    field(:algo, any())
    field(:params, any())
    field(:value, any())
    field(:purpose, any())
    field(:process_group_name, any())
    field(:landing_node, any())
  end
end

alias StrapSoftPrivKeyStoreProvider.Model.Pubkey
alias StrapPrivKeyStoreProvider.Protocol.PublicKeyOps

defimpl PublicKeyOps, for: Pubkey do
  alias ExCcrypto.Asymkey.AsymkeyEncrypt
  alias ExCcrypto.Asymkey.AsymkeyEncryptContextBuilder
  alias ExCcrypto.ContextConfig
  alias ExCcrypto.Asymkey.AsymkeyVerify

  def verify_data(%Pubkey{} = pub, data, signature, _opts) do
    AsymkeyVerify.verify_init(signature, %{verification_key: pub.value})
    |> AsymkeyVerify.verify_update(data)
    |> AsymkeyVerify.verify_final(ContextConfig.get(signature, :signature))
  end

  def encrypt_data(%Pubkey{} = pub, data, _opts) do
    AsymkeyEncryptContextBuilder.encrypt_context(pub.algo)
    |> ContextConfig.set(:add_encryption_key, pub.value)
    |> AsymkeyEncrypt.encrypt_init()
    |> AsymkeyEncrypt.encrypt_update(data)
    |> AsymkeyEncrypt.encrypt_final()
  end
end
