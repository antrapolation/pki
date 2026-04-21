defmodule StrapPrivKeyStoreProvider.KeyGenerator do
  alias StrapPrivKeyStoreProvider.RemoteUtils
  alias StrapPrivKeyStoreProvider.Protocol.KeyGeneratorProtocol

  def generate_key(ctx, opts \\ %{})

  def generate_key(%{process_group_name: gname} = ctx, opts) when not is_nil(gname) do
    RemoteUtils.call(gname, {:generate_key, ctx, opts}, opts)
  end

  defdelegate generate_key(ctx, opts), to: KeyGeneratorProtocol
end
