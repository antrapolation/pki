defmodule StrapSofthsmPrivKeyStoreProvider.Model.KeypairType do
  use TypedStruct

  typedstruct do
    field(:algo_string, any())
    field(:algo, any())
    field(:params, any())
    field(:opts, any())
    field(:purpose, any())
    field(:process_group_name, any())
    field(:landing_node, any())
  end
end

alias StrapPrivKeyStoreProvider.Protocol.KeyGeneratorProtocol
alias StrapSofthsmPrivKeyStoreProvider.Model.KeypairType

defimpl KeyGeneratorProtocol, for: KeypairType do
  alias StrapPrivKeyStoreProvider.RemoteUtils

  def generate_key(%KeypairType{} = type, opts \\ %{}) do
    case type.process_group_name do
      nil ->
        # Locally (this shouldn't happen if we follow the pattern)
        {:error, :no_process_group_name}

      gname ->
        RemoteUtils.call(gname, {:generate_key, type, opts})
    end
  end
end
