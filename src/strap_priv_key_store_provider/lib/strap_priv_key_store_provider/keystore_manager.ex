defmodule StrapPrivKeyStoreProvider.KeystoreManager do
  alias StrapPrivKeyStoreProvider.RemoteUtils
  alias StrapPrivKeyStoreProvider.Protocol.KeystoreManagerProtocol
  def to_keypair(keystore, auth_token, opts \\ %{})

  def to_keypair(%{process_group_name: gname} = ctx, auth_token, opts) when not is_nil(gname) do
    RemoteUtils.call(gname, {:keystore_to_keypair, ctx, auth_token, opts}, opts)
  end

  defdelegate to_keypair(ks, auth_token, opts), to: KeystoreManagerProtocol

  def update_auth_token(keystore, existing_auth_token, new_auth_token, opts \\ %{})

  def update_auth_token(%{process_group_name: gname} = ctx, existing, new, opts)
      when not is_nil(gname) do
    RemoteUtils.call(gname, {:update_keystore_auth_token, ctx, existing, new, opts}, opts)
  end

  defdelegate update_auth_token(ks, old, new, opts), to: KeystoreManagerProtocol
end
