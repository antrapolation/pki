defmodule StrapSofthsmPrivKeyStoreProvider.Model.SofthsmKeypair do
  use TypedStruct

  typedstruct do
    field(:pub_key, StrapSofthsmPrivKeyStoreProvider.Model.SofthsmPubKey.t())
    field(:priv_key, StrapSofthsmPrivKeyStoreProvider.Model.SofthsmPrivKey.t())
    field(:purpose, any())
  end
end

alias StrapSofthsmPrivKeyStoreProvider.Model.SofthsmKeypair
alias StrapPrivKeyStoreProvider.Protocol.KeypairEngine
alias StrapPrivKeyStoreProvider.RemoteUtils

defimpl KeypairEngine, for: SofthsmKeypair do
  def keypair_purpose(keypair, _opts), do: keypair.purpose

  def to_keystore(keypair, auth_token, opts) do
    RemoteUtils.call(
      keypair.priv_key.process_group_name,
      {:keypair_to_keystore, keypair, auth_token, opts}
    )
  end

  def set_keypair_info(keypair, key, value, opts) do
    RemoteUtils.call(
      keypair.priv_key.process_group_name,
      {:set_keypair_info, keypair, key, value, opts}
    )
  end

  def remove_keypair_info(keypair, key, opts) do
    RemoteUtils.call(
      keypair.priv_key.process_group_name,
      {:remove_keypair_info, keypair, key, opts}
    )
  end

  def get_keypair_info(keypair, key, opts) do
    RemoteUtils.call(keypair.priv_key.process_group_name, {:get_keypair_info, keypair, key, opts})
  end

  def public_key(keypair, _opts), do: keypair.pub_key
  def private_key(keypair, _opts), do: keypair.priv_key
end
