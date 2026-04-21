defmodule StrapSofthsmPrivKeyStoreProvider.SofthsmPrivkeyProviderProcess do
  alias StrapPrivKeyStoreProvider.Protocol.ProviderInfo
  alias StrapSofthsmPrivKeyStoreProvider.SofthsmBackend
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

  def init(opts) do
    case SofthsmBackend.initialize(opts) do
      {:ok, backend_state} ->
        {:ok, %{opts: opts, backend: backend_state}}

      error ->
        {:stop, error}
    end
  end

  def handle_call({:get_provider_context, opts}, _from, state) do
    {:reply,
     {:ok,
      %StrapSofthsmPrivKeyStoreProvider.Model.SofthsmPrivKeyProvider{
        StrapSofthsmPrivKeyStoreProvider.Model.SofthsmPrivKeyProvider.new(state.opts)
        | process_group_name: Map.get(opts, :process_group_name),
          landing_node: Map.get(opts, :node)
      }}, state}
  end

  def handle_call({:supported_key_types, ctx}, _from, state) do
    {:reply, ProviderInfo.supported_key_types(ctx), state}
  end

  def handle_call({:generate_key, type, _opts}, _from, state) do
    case SofthsmBackend.generate_key(type, state.backend) do
      {:ok, %{pub_key: pub, priv_key: priv}} ->
        kp = %StrapSofthsmPrivKeyStoreProvider.Model.SofthsmKeypair{
          pub_key: pub,
          priv_key: priv,
          purpose: type.purpose
        }

        {:reply, {:ok, kp}, state}

      error ->
        {:reply, error, state}
    end
  end

  def handle_call({:public_key, ctx, _opts}, _from, state) do
    # ctx is likely SofthsmKeypair or SofthsmPubKey
    case ctx do
      %StrapSofthsmPrivKeyStoreProvider.Model.SofthsmKeypair{pub_key: pub} ->
        {:reply, {:ok, pub}, state}

      %StrapSofthsmPrivKeyStoreProvider.Model.SofthsmPubKey{} = pub ->
        {:reply, {:ok, pub}, state}

      _ ->
        {:reply, {:error, :invalid_context}, state}
    end
  end

  def handle_call({:private_key, ctx, _opts}, _from, state) do
    case ctx do
      %StrapSofthsmPrivKeyStoreProvider.Model.SofthsmKeypair{priv_key: priv} ->
        {:reply, {:ok, priv}, state}

      %StrapSofthsmPrivKeyStoreProvider.Model.SofthsmPrivKey{} = priv ->
        {:reply, {:ok, priv}, state}

      _ ->
        {:reply, {:error, :invalid_context}, state}
    end
  end

  def handle_call({:sign_data, ctx, data, opts}, _from, state) do
    # ctx is SofthsmPrivKey
    res = SofthsmBackend.sign(ctx.key_id, ctx.algo, data, opts, state.backend)
    {:reply, res, state}
  end

  def handle_call({:verify_data, ctx, data, signature, opts}, _from, state) do
    # ctx is SofthsmPubKey
    res = SofthsmBackend.verify(ctx.key_id, ctx.algo, data, signature, opts, state.backend)
    {:reply, res, state}
  end

  def handle_call({:encrypt_data, ctx, data, opts}, _from, state) do
    # ctx is SofthsmPubKey
    res = SofthsmBackend.encrypt(ctx.key_id, ctx.algo, data, opts, state.backend)
    {:reply, res, state}
  end

  def handle_call({:decrypt_data, ctx, data, opts}, _from, state) do
    # ctx is SofthsmPrivKey
    res = SofthsmBackend.decrypt(ctx.key_id, ctx.algo, data, opts, state.backend)
    {:reply, res, state}
  end

  def handle_call({:keypair_to_keystore, kp, auth_token, _opts}, _from, state) do
    # User requested to "set the slot password" here.
    current_pin = Map.get(state.backend.opts, :pin, "1234")

    case SofthsmBackend.set_pin(current_pin, auth_token, state.backend) do
      :ok ->
        # Update our state with the new PIN
        new_state = put_in(state, [:backend, :opts, :pin], auth_token)

        ks = %StrapSofthsmPrivKeyStoreProvider.Model.SofthsmKeystore{
          key_id: kp.priv_key.key_id,
          algo: kp.priv_key.algo,
          params: kp.priv_key.params,
          purpose: kp.purpose,
          process_group_name: kp.priv_key.process_group_name,
          landing_node: kp.priv_key.landing_node
        }

        {:reply, {:ok, ks}, new_state}

      error ->
        {:reply, error, state}
    end
  end

  def handle_call({:keystore_to_keypair, ks, _auth_token, _opts}, _from, state) do
    # Return private key struct
    priv = %StrapSofthsmPrivKeyStoreProvider.Model.SofthsmPrivKey{
      key_id: ks.key_id,
      slot: Map.get(state.backend.opts, :slot, 0),
      algo: ks.algo,
      params: ks.params,
      process_group_name: ks.process_group_name,
      landing_node: ks.landing_node
    }

    {:reply, {:ok, priv}, state}
  end

  def handle_call({:update_keystore_auth_token, _ks, existing, new, _opts}, _from, state) do
    case SofthsmBackend.set_pin(existing, new, state.backend) do
      :ok ->
        new_state = put_in(state, [:backend, :opts, :pin], new)
        {:reply, :ok, new_state}

      error ->
        {:reply, error, state}
    end
  end

  def handle_call({:generate_cert, _ctx, _owner, _issuer, _opts}, _from, state) do
    # We might use ex_ccrypto for cert generation but with HSM signing callback
    {:reply, {:error, :not_implemented_pkcs11_gen_cert}, state}
  end

  def handle_call({:issue_cert, _ctx, _owner, _issuer, _opts}, _from, state) do
    {:reply, {:error, :not_implemented_pkcs11_issue_cert}, state}
  end

  def handle_call({:generate_csr, _ctx, _owner, _opts}, _from, state) do
    {:reply, {:error, :not_implemented_pkcs11_gen_csr}, state}
  end
end
