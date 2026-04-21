defmodule StrapSoftPrivKeyStoreProvider.SoftPrivkeyProviderProcess do
  alias StrapPrivKeyStoreProvider.Protocol.CSRGeneratorProtocol
  alias StrapPrivKeyStoreProvider.Protocol.CertManagerProtocol
  alias StrapPrivKeyStoreProvider.Protocol.KeystoreManagerProtocol
  alias StrapPrivKeyStoreProvider.Protocol.PublicKeyOps
  alias StrapPrivKeyStoreProvider.Protocol.PrivateKeyOps
  alias StrapPrivKeyStoreProvider.Protocol.KeypairEngine
  alias StrapPrivKeyStoreProvider.Protocol.KeyGeneratorProtocol
  alias StrapSoftPrivKeyStoreProvider.Model.SoftPrivKeyProvider
  alias StrapPrivKeyStoreProvider.Protocol.ProviderInfo
  use GenServer

  def start_link(opts \\ %{}) do
    gname = Map.get(opts, :group)

    case gname do
      nil ->
        GenServer.start_link(__MODULE__, opts)

      _ ->
        GenServer.start_link(__MODULE__, opts,
          name: {:via, StrapProcReg, %{group: gname, operation: :register}}
        )
    end
  end

  def stop(pid) do
    GenServer.stop(pid)
  end

  def init(_) do
    {:ok, %{}}
  end

  def handle_call({:get_provider_context, opts}, _from, state) do
    {:reply,
     {:ok,
      %SoftPrivKeyProvider{
        SoftPrivKeyProvider.new()
        | process_group_name: Map.get(opts, :process_group_name),
          landing_node: Map.get(opts, :node)
      }}, state}
  end

  def handle_call({:supported_key_types, ctx}, _from, state) do
    {:reply, ProviderInfo.supported_key_types(ctx), state}
  end

  def handle_call({:generate_key, ctx, opts}, _from, state) do
    {:reply, KeyGeneratorProtocol.generate_key(ctx, opts), state}
  end

  def handle_call({:public_key, ctx, opts}, _from, state) do
    {:reply, KeypairEngine.public_key(ctx, opts), state}
  end

  def handle_call({:private_key, ctx, opts}, _from, state) do
    {:reply, KeypairEngine.private_key(ctx, opts), state}
  end

  def handle_call({:sign_data, ctx, data, opts}, _from, state) do
    {:reply, PrivateKeyOps.sign_data(ctx, data, opts), state}
  end

  def handle_call({:verify_data, ctx, data, signature, opts}, _from, state) do
    {:reply, PublicKeyOps.verify_data(ctx, data, signature, opts), state}
  end

  def handle_call({:keypair_to_keystore, ctx, auth_token, opts}, _from, state) do
    {:reply, KeypairEngine.to_keystore(ctx, auth_token, opts), state}
  end

  def handle_call({:keystore_to_keypair, ctx, auth_token, opts}, _from, state) do
    {:reply, KeystoreManagerProtocol.to_keypair(ctx, auth_token, opts), state}
  end

  def handle_call({:update_keystore_auth_token, ctx, existing, new, opts}, _from, state) do
    {:reply, KeystoreManagerProtocol.update_auth_token(ctx, existing, new, opts), state}
  end

  def handle_call({:generate_cert, ctx, owner, issuer, opts}, _from, state) do
    {:reply, CertManagerProtocol.generate_cert(ctx, owner, issuer, opts), state}
  end

  def handle_call({:issue_cert, ctx, owner, issuer, opts}, _from, state) do
    {:reply, CertManagerProtocol.issue_cert(ctx, owner, issuer, opts), state}
  end

  def handle_call({:generate_csr, ctx, owner, opts}, _from, state) do
    {:reply, CSRGeneratorProtocol.generate(ctx, owner, opts), state}
  end
end
