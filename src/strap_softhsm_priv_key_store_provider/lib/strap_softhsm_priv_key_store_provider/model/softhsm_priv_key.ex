defmodule StrapSofthsmPrivKeyStoreProvider.Model.SofthsmPrivKey do
  use TypedStruct

  typedstruct do
    field(:key_id, any())
    field(:slot, any())
    field(:algo, any())
    field(:params, any())
    field(:process_group_name, any())
    field(:landing_node, any())
  end

  def new(opts \\ %{}) do
    %__MODULE__{
      key_id: Map.get(opts, :key_id),
      slot: Map.get(opts, :slot),
      algo: Map.get(opts, :algo),
      params: Map.get(opts, :params),
      process_group_name: Map.get(opts, :process_group_name),
      landing_node: Map.get(opts, :landing_node)
    }
  end
end

alias StrapSofthsmPrivKeyStoreProvider.Model.SofthsmPrivKey
alias StrapPrivKeyStoreProvider.Protocol.PrivateKeyOps
alias StrapPrivKeyStoreProvider.RemoteUtils

defimpl PrivateKeyOps, for: SofthsmPrivKey do
  def sign_data(key, data, opts) do
    RemoteUtils.call(key.process_group_name, {:sign_data, key, data, opts})
  end

  def decrypt_data(key, _pubkey, data, opts) do
    RemoteUtils.call(key.process_group_name, {:decrypt_data, key, data, opts})
  end
end
