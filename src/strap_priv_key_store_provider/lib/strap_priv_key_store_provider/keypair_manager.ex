defmodule StrapPrivKeyStoreProvider.KeypairManager do
  alias StrapPrivKeyStoreProvider.RemoteUtils
  alias StrapPrivKeyStoreProvider.Protocol.PublicKeyOps
  alias StrapPrivKeyStoreProvider.Protocol.PrivateKeyOps
  alias StrapPrivKeyStoreProvider.Protocol.KeypairEngine

  def keypair_purpose(ctx, opts \\ %{})

  def keypair_purpose(%{process_group_name: gname} = ctx, opts) when not is_nil(gname) do
    RemoteUtils.call(gname, {:keypair_purpose, ctx, opts}, opts)
  end

  defdelegate keypair_purpose(keypair, opts), to: KeypairEngine

  def to_keystore(ctx, auth_token, opts \\ %{})

  def to_keystore(%{process_group_name: gname} = ctx, auth_token, opts) when not is_nil(gname) do
    RemoteUtils.call(gname, {:keypair_to_keystore, ctx, auth_token, opts}, opts)
  end

  defdelegate to_keystore(keypair, auth_token, opts), to: KeypairEngine

  def set_keypair_info(keypair, key, value, opts \\ %{})

  def set_keypair_info(%{process_group_name: gname} = ctx, key, value, opts)
      when not is_nil(gname) do
    RemoteUtils.call(gname, {:set_keypair_info, ctx, key, value, opts}, opts)
  end

  defdelegate set_keypair_info(keypair, key, value, opts), to: KeypairEngine

  def remove_keypair_info(keypair, key, opts \\ %{})

  def remove_keypair_info(%{process_group_name: gname} = ctx, key, opts) when not is_nil(gname) do
    RemoteUtils.call(gname, {:remove_keypair_info, ctx, key, opts}, opts)
  end

  defdelegate remove_keypair_info(keypair, key, opts), to: KeypairEngine

  def get_keypair_info(keypair, key, opts \\ %{})

  def get_keypair_info(%{process_group_name: gname} = ctx, key, opts) when not is_nil(gname) do
    RemoteUtils.call(gname, {:get_keypair_info, ctx, key, opts}, opts)
  end

  defdelegate get_keypair_info(keypair, key, opts), to: KeypairEngine

  def public_key(keypair, opts \\ %{})

  def public_key(%{process_group_name: gname} = ctx, opts) when not is_nil(gname) do
    RemoteUtils.call(gname, {:public_key, ctx, opts}, opts)
  end

  defdelegate public_key(keypair, opts), to: KeypairEngine

  def private_key(keypair, opts \\ %{})

  def private_key(%{process_group_name: gname} = ctx, opts) when not is_nil(gname) do
    RemoteUtils.call(gname, {:private_key, ctx, opts}, opts)
  end

  defdelegate private_key(keypair, opts), to: KeypairEngine

  def sign_data(keypair, data, opts \\ %{})

  def sign_data(%{process_group_name: gname} = ctx, data, opts) when not is_nil(gname) do
    RemoteUtils.call(gname, {:sign_data, ctx, data, opts}, opts)
  end

  defdelegate sign_data(keypair, data, opts), to: PrivateKeyOps

  def decrypt_data(keypair, cipher, opts \\ %{})

  def decrypt_data(%{process_group_name: gname} = ctx, cipher, opts) when not is_nil(gname) do
    RemoteUtils.call(gname, {:decrypt_data, ctx, cipher, opts}, opts)
  end

  defdelegate decrypt_data(keypair, cipher, opts), to: PrivateKeyOps

  def verify_data(keypair, data, signature, opts \\ %{})

  def verify_data(%{process_group_name: gname} = ctx, data, signature, opts)
      when not is_nil(gname) do
    RemoteUtils.call(gname, {:verify_data, ctx, data, signature, opts}, opts)
  end

  defdelegate verify_data(keypair, data, signature, opts), to: PublicKeyOps

  def encrypt_data(keypair, data, opts \\ %{})

  def encrypt_data(%{process_group_name: gname} = ctx, data, opts) when not is_nil(gname) do
    RemoteUtils.call(gname, {:verify_data, ctx, data, opts}, opts)
  end

  defdelegate encrypt_data(keypair, data, opts), to: PublicKeyOps
end
