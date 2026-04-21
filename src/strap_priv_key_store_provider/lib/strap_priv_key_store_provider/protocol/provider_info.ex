defprotocol StrapPrivKeyStoreProvider.Protocol.ProviderInfo do
  @doc """
  Get supported key types.
  """
  def supported_key_types(ctx, opts \\ %{})

  def get_provider_context(ctx, opts)
end
