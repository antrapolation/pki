defmodule StrapSoftPrivKeyStoreProvider.Model.KeypairType do
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
alias StrapSoftPrivKeyStoreProvider.Model.KeypairType

defimpl KeyGeneratorProtocol, for: KeypairType do
  alias StrapSoftPrivKeyStoreProvider.Model.Keypair
  alias ExCcrypto.Asymkey
  alias ExCcrypto.ContextConfig
  alias ExCcrypto.Asymkey.AsymkeyContextBuilder

  def generate_key(%KeypairType{} = type, _opts \\ %{}) do
    with {:ok, keypair} <-
           AsymkeyContextBuilder.generator_context(type.algo)
           |> ContextConfig.set(:params, type.params)
           |> Asymkey.generate() do
      {:ok,
       %Keypair{
         purpose: type.purpose,
         algo: type.algo,
         params: type.params,
         value: keypair,
         process_group_name: type.process_group_name,
         landing_node: type.landing_node
       }}
    end
  end
end
