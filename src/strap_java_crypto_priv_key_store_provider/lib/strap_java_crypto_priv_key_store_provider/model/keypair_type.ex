defmodule StrapJavaCryptoPrivKeyStoreProvider.Model.KeypairType do
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
alias StrapJavaCryptoPrivKeyStoreProvider.Model.KeypairType

defimpl KeyGeneratorProtocol, for: KeypairType do
  alias StrapJavaCryptoPrivKeyStoreProvider.Model.Keypair

  def generate_key(%KeypairType{} = type, opts \\ %{}) do
    group = Map.get(opts, :crypto_group, :ap_java_crypto)
    safe_opts = Map.drop(opts, [:timeout])

    case ApJavaCrypto.generate_keypair(type.algo, Map.put(safe_opts, :group_name, group)) do
      {:ok, {algo, :private_key, privKey}, {algo, :public_key, pubKey}} ->
        {:ok,
         %Keypair{
           purpose: type.purpose,
           algo: type.algo,
           params: type.params,
           value: %{
             public_key: {algo, :public_key, pubKey},
             private_key: {algo, :private_key, privKey}
           },
           process_group_name: type.process_group_name,
           landing_node: type.landing_node
         }}

      err ->
        err
    end
  end
end
