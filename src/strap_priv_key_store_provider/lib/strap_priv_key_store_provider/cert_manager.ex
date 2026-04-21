defmodule StrapPrivKeyStoreProvider.CertManager do
  alias StrapPrivKeyStoreProvider.RemoteUtils
  alias StrapPrivKeyStoreProvider.Protocol.CertManagerProtocol
  def generate_cert(keystore, owner, issuer, opts \\ %{})

  def generate_cert(%{process_group_name: gname} = ctx, owner, issuer, opts)
      when not is_nil(gname) do
    RemoteUtils.call(gname, {:generate_cert, ctx, owner, issuer, opts}, opts)
  end

  defdelegate generate_cert(ks, owner, issuer, opts), to: CertManagerProtocol

  def issue_cert(keystore, owner, issuer, opts \\ %{})

  def issue_cert(%{process_group_name: gname} = ctx, owner, issuer, opts)
      when not is_nil(gname) do
    RemoteUtils.call(gname, {:issue_cert, ctx, owner, issuer, opts}, opts)
  end

  defdelegate issue_cert(ks, owner, issuer, opts), to: CertManagerProtocol
end
