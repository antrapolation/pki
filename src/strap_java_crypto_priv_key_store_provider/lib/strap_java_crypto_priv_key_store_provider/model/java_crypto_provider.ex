defmodule StrapJavaCryptoPrivKeyStoreProvider.Model.JavaCryptoProvider do
  alias StrapJavaCryptoPrivKeyStoreProvider.MixProject
  alias StrapJavaCryptoPrivKeyStoreProvider.Model.JavaCryptoProvider
  use TypedStruct

  typedstruct do
    field(:inst_id, any())
    field(:name, any())
    field(:version, any())
    field(:process_group_name, any())
    field(:landing_node, any())
  end

  def new() do
    %JavaCryptoProvider{
      name: "Strap Java Crypto Private Key Provider",
      version: Keyword.get(MixProject.project(), :version)
    }
  end
end

alias StrapPrivKeyStoreProvider.Protocol.ProviderInfo
alias StrapJavaCryptoPrivKeyStoreProvider.Model.JavaCryptoProvider

defimpl ProviderInfo, for: JavaCryptoProvider do
  alias StrapJavaCryptoPrivKeyStoreProvider.Model.KeypairType

  def get_provider_context(_ctx, _opts) do
    JavaCryptoProvider.new()
  end

  def supported_key_types(prov, %{purpose: :enc} = opts) do
    fetch_kem_algos(prov, opts)
  end

  def supported_key_types(prov, %{purpose: purpose} = opts)
      when purpose == :sign_enc or purpose == :all do
    with {:ok, signs} <- fetch_signing_algos(prov, opts),
         {:ok, kems} <- fetch_kem_algos(prov, opts) do
      {:ok, signs ++ kems}
    end
  end

  def supported_key_types(prov, opts) do
    # :sign or nil reach here
    fetch_signing_algos(prov, opts)
  end

  defp fetch_signing_algos(prov, opts) do
    group = Map.get(opts, :crypto_group, :ap_java_crypto)

    case ApJavaCrypto.supported_pqc_signing_algo(%{group_name: group}) do
      {:ok, algos} ->
        {:ok,
         Enum.map(algos, fn algo ->
           %KeypairType{
             algo: algo,
             algo_string: to_string(algo),
             purpose: :sign,
             process_group_name: prov.process_group_name,
             landing_node: prov.landing_node
           }
         end)}

      err ->
        err
    end
  end

  defp fetch_kem_algos(prov, opts) do
    group = Map.get(opts, :crypto_group, :ap_java_crypto)

    case ApJavaCrypto.supported_pqc_kem_algo(%{group_name: group}) do
      {:ok, algos} ->
        {:ok,
         Enum.map(algos, fn algo ->
           %KeypairType{
             algo: algo,
             algo_string: to_string(algo),
             purpose: :enc,
             process_group_name: prov.process_group_name,
             landing_node: prov.landing_node
           }
         end)}

      err ->
        err
    end
  end
end
