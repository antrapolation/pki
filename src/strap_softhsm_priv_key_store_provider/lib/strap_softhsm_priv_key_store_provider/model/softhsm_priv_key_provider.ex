defmodule StrapSofthsmPrivKeyStoreProvider.Model.SofthsmPrivKeyProvider do
  alias StrapSofthsmPrivKeyStoreProvider.Model.SofthsmPrivKeyProvider
  use TypedStruct

  typedstruct do
    field(:inst_id, any())
    field(:name, any())
    field(:version, any())
    field(:process_group_name, any())
    field(:landing_node, any())
    field(:slot, any())
    field(:token_label, any())
    field(:pin, any())
  end

  def new(opts \\ %{}) do
    %SofthsmPrivKeyProvider{
      name: "SoftHSM PKCS#11 Private Key Provider",
      version: "0.1.0",
      slot: Map.get(opts, :slot, 0),
      token_label: Map.get(opts, :token_label),
      pin: Map.get(opts, :pin)
    }
  end
end

alias StrapPrivKeyStoreProvider.Protocol.ProviderInfo
alias StrapSofthsmPrivKeyStoreProvider.Model.SofthsmPrivKeyProvider

defimpl ProviderInfo, for: SofthsmPrivKeyProvider do
  alias StrapSofthsmPrivKeyStoreProvider.Model.KeypairType

  def get_provider_context(ctx, opts) do
    # Merge options into the context
    %{
      ctx
      | process_group_name: Map.get(opts, :process_group_name),
        landing_node: Map.get(opts, :node)
    }
  end

  def supported_key_types(prov, %{purpose: :enc}) do
    {:ok, build_enc_keytypes(prov)}
  end

  def supported_key_types(prov, %{purpose: purpose})
      when purpose == :sign_enc or purpose == :all do
    {:ok, build_signing_keytypes(prov) ++ build_enc_keytypes(prov)}
  end

  def supported_key_types(prov, _) do
    {:ok, build_signing_keytypes(prov)}
  end

  defp build_signing_keytypes(%SofthsmPrivKeyProvider{} = prov) do
    [
      %KeypairType{
        algo: :rsa,
        params: 2048,
        algo_string: "RSA-2048",
        purpose: :sign,
        process_group_name: prov.process_group_name,
        landing_node: prov.landing_node
      },
      %KeypairType{
        algo: :ecc,
        params: :secp256r1,
        algo_string: "ECC-secp256r1",
        purpose: :sign,
        process_group_name: prov.process_group_name,
        landing_node: prov.landing_node
      }
    ]
  end

  defp build_enc_keytypes(prov) do
    [
      %KeypairType{
        algo: :rsa,
        params: 2048,
        algo_string: "RSA-2048",
        purpose: :enc,
        process_group_name: prov.process_group_name,
        landing_node: prov.landing_node
      }
    ]
  end
end
