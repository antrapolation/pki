defmodule StrapPrivKeyStoreProvider.CSRGenerator do
  alias StrapPrivKeyStoreProvider.Protocol.CSRGeneratorProtocol
  alias StrapPrivKeyStoreProvider.RemoteUtils
  def generate(keystore, owner, opts \\ %{})

  def generate(%{process_group_name: gname} = ctx, owner, opts) when not is_nil(gname) do
    RemoteUtils.call(gname, {:generate_csr, ctx, owner, opts}, opts)
  end

  defdelegate generate(keystore, owner, opts), to: CSRGeneratorProtocol
end
