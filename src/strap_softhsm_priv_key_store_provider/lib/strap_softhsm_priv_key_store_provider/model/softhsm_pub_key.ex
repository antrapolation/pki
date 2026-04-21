defmodule StrapSofthsmPrivKeyStoreProvider.Model.SofthsmPubKey do
  use TypedStruct

  typedstruct do
    field(:material, any())
    field(:algo, any())
    field(:params, any())
    field(:key_id, any())
    field(:process_group_name, any())
    field(:landing_node, any())
  end

  def new(opts \\ %{}) do
    %__MODULE__{
      material: Map.get(opts, :material),
      algo: Map.get(opts, :algo),
      params: Map.get(opts, :params),
      key_id: Map.get(opts, :key_id),
      process_group_name: Map.get(opts, :process_group_name),
      landing_node: Map.get(opts, :landing_node)
    }
  end
end

alias StrapSofthsmPrivKeyStoreProvider.Model.SofthsmPubKey
alias StrapPrivKeyStoreProvider.Protocol.PublicKeyOps
alias StrapPrivKeyStoreProvider.RemoteUtils

defimpl PublicKeyOps, for: SofthsmPubKey do
  def verify_data(key, data, signature, opts) do
    RemoteUtils.call(key.process_group_name, {:verify_data, key, data, signature, opts})
  end

  def encrypt_data(key, data, opts) do
    RemoteUtils.call(key.process_group_name, {:encrypt_data, key, data, opts})
  end
end
