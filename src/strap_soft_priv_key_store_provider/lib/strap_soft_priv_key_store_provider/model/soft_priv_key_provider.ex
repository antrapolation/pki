defmodule StrapSoftPrivKeyStoreProvider.Model.SoftPrivKeyProvider do
  alias StrapSoftPrivKeyStoreProvider.MixProject
  alias StrapSoftPrivKeyStoreProvider.Model.SoftPrivKeyProvider
  use TypedStruct

  typedstruct do
    field(:inst_id, any())
    field(:name, any())
    field(:version, any())
    field(:process_group_name, any())
    field(:landing_node, any())
  end

  def new() do
    %SoftPrivKeyProvider{
      name: "ExCcrypto Software Based Private Key Provider",
      version: Keyword.get(MixProject.project(), :version)
    }
  end
end

alias StrapPrivKeyStoreProvider.Protocol.ProviderInfo
alias StrapSoftPrivKeyStoreProvider.Model.SoftPrivKeyProvider

defimpl ProviderInfo, for: SoftPrivKeyProvider do
  alias StrapSoftPrivKeyStoreProvider.Model.KeypairType
  alias ExCcrypto.ContextConfig
  alias ExCcrypto.Asymkey.AsymkeyContextBuilder

  def get_provider_context(_ctx, _opts) do
    SoftPrivKeyProvider.new()
  end

  def supported_key_types(prov, %{purpose: :enc}) do
    {:ok, build_enc_keytypes(prov)}
  end

  def supported_key_types(prov, %{purpose: purpose})
      when purpose == :sign_enc or purpose == :all do
    {:ok, build_signing_keytypes(prov) ++ build_enc_keytypes(prov)}
  end

  def supported_key_types(prov, _) do
    # :sign or nil reach here 
    {:ok, build_signing_keytypes(prov)}
  end

  defp build_signing_keytypes(%SoftPrivKeyProvider{} = prov) do
    Enum.reduce(
      AsymkeyContextBuilder.generator_context(:rsa) |> ContextConfig.get(:supported_keysizes),
      [],
      fn keysize, acc ->
        acc ++
          [
            %KeypairType{
              algo: :rsa,
              params: keysize,
              algo_string: "RSA-#{keysize}",
              purpose: :sign,
              process_group_name: prov.process_group_name,
              landing_node: prov.landing_node
            }
          ]
      end
    ) ++
      Enum.reduce(
        AsymkeyContextBuilder.generator_context(:ecc) |> ContextConfig.get(:supported_curves),
        [],
        fn curve, acc ->
          case curve do
            x when x in [:x25519, :x448] ->
              acc

            _ ->
              acc ++
                [
                  %KeypairType{
                    algo: :ecc,
                    params: curve,
                    algo_string: "ECC-#{curve}",
                    purpose: :sign,
                    process_group_name: prov.process_group_name,
                    landing_node: prov.landing_node
                  }
                ]
          end
        end
      )
  end

  defp build_enc_keytypes(prov) do
    Enum.reduce(
      AsymkeyContextBuilder.generator_context(:rsa) |> ContextConfig.get(:supported_keysizes),
      [],
      fn keysize, acc ->
        acc ++
          [
            %KeypairType{
              algo: :rsa,
              params: keysize,
              algo_string: "RSA-#{keysize}",
              purpose: :enc,
              process_group_name: prov.process_group_name,
              landing_node: prov.landing_node
            }
          ]
      end
    ) ++
      Enum.reduce(
        AsymkeyContextBuilder.generator_context(:ecc) |> ContextConfig.get(:supported_curves),
        [],
        fn curve, acc ->
          case curve do
            x when x in [:ed25519, :ed448] ->
              acc

            _ ->
              acc ++
                [
                  %KeypairType{
                    algo: :ecc,
                    params: curve,
                    algo_string: "ECC-#{curve}",
                    purpose: :enc,
                    process_group_name: prov.process_group_name,
                    landing_node: prov.landing_node
                  }
                ]
          end
        end
      )
  end
end
