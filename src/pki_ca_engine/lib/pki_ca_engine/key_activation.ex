defmodule PkiCaEngine.KeyActivation do
  @moduledoc """
  Day-to-day key activation via threshold share reconstruction.
  GenServer holds reconstructed private keys in memory.
  Share lookup now uses Mnesia instead of Ecto.
  """
  use GenServer

  alias PkiMnesia.Repo
  alias PkiMnesia.Structs.ThresholdShare
  alias PkiCaEngine.KeyCeremony.ShareEncryption

  # -- Client API --

  def start_link(opts) do
    name = opts[:name] || __MODULE__
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  def submit_share(server \\ __MODULE__, issuer_key_id, custodian_name, password) do
    GenServer.call(server, {:submit_share, issuer_key_id, custodian_name, password})
  end

  def is_active?(server \\ __MODULE__, issuer_key_id) do
    GenServer.call(server, {:is_active, issuer_key_id})
  end

  def deactivate(server \\ __MODULE__, issuer_key_id) do
    GenServer.call(server, {:deactivate, issuer_key_id})
  end

  def get_active_key(server \\ __MODULE__, issuer_key_id) do
    GenServer.call(server, {:get_active_key, issuer_key_id})
  end

  def dev_activate(server \\ __MODULE__, issuer_key_id, private_key_der) do
    if Application.get_env(:pki_ca_engine, :allow_dev_activate, false) do
      GenServer.call(server, {:dev_activate, issuer_key_id, private_key_der})
    else
      {:error, :not_available_in_production}
    end
  end

  # -- Server Callbacks --

  @impl true
  def init(opts) do
    timeout_ms = opts[:timeout_ms] || 3_600_000

    {:ok, %{
      active_keys: %{},
      pending_shares: %{},
      custodians_submitted: %{},
      min_shares_cache: %{},
      timeout_ms: timeout_ms
    }}
  end

  @impl true
  def handle_call({:submit_share, issuer_key_id, custodian_name, password}, _from, state) do
    submitted_set = Map.get(state.custodians_submitted, issuer_key_id, MapSet.new())

    if MapSet.member?(submitted_set, custodian_name) do
      {:reply, {:error, :already_submitted}, state}
    else
      # Look up share from Mnesia by issuer_key_id + custodian_name
      case Repo.where(ThresholdShare, fn s ->
        s.issuer_key_id == issuer_key_id and s.custodian_name == custodian_name
      end) do
        {:ok, []} ->
          {:reply, {:error, :share_not_found}, state}

        {:ok, [record | _]} ->
          case ShareEncryption.decrypt_share(record.encrypted_share, password) do
            {:error, :decryption_failed} ->
              {:reply, {:error, :decryption_failed}, state}

            {:ok, decrypted_share} ->
              new_submitted = Map.put(
                state.custodians_submitted,
                issuer_key_id,
                MapSet.put(submitted_set, custodian_name)
              )

              pending = Map.get(state.pending_shares, issuer_key_id, [])
              new_pending = [decrypted_share | pending]

              min_shares = case Map.get(state.min_shares_cache, issuer_key_id) do
                nil -> record.min_shares
                cached -> cached
              end

              if length(new_pending) >= min_shares do
                case PkiCrypto.Shamir.recover(new_pending) do
                  {:ok, secret} ->
                    timer_ref = Process.send_after(self(), {:timeout, issuer_key_id}, state.timeout_ms)

                    new_state = %{state |
                      active_keys: Map.put(state.active_keys, issuer_key_id, %{secret: secret, timer_ref: timer_ref}),
                      pending_shares: Map.delete(state.pending_shares, issuer_key_id),
                      custodians_submitted: Map.delete(state.custodians_submitted, issuer_key_id),
                      min_shares_cache: Map.delete(state.min_shares_cache, issuer_key_id)
                    }

                    {:reply, {:ok, :key_activated}, new_state}

                  {:error, reason} ->
                    {:reply, {:error, {:reconstruction_failed, reason}}, state}
                end
              else
                new_state = %{state |
                  pending_shares: Map.put(state.pending_shares, issuer_key_id, new_pending),
                  custodians_submitted: new_submitted,
                  min_shares_cache: Map.put(state.min_shares_cache, issuer_key_id, min_shares)
                }

                {:reply, {:ok, :share_accepted}, new_state}
              end
          end

        {:error, reason} ->
          {:reply, {:error, {:share_lookup_failed, reason}}, state}
      end
    end
  end

  @impl true
  def handle_call({:is_active, issuer_key_id}, _from, state) do
    {:reply, Map.has_key?(state.active_keys, issuer_key_id), state}
  end

  @impl true
  def handle_call({:deactivate, issuer_key_id}, _from, state) do
    case Map.pop(state.active_keys, issuer_key_id) do
      {nil, _} ->
        {:reply, {:error, :not_active}, state}

      {%{timer_ref: ref}, new_active} ->
        Process.cancel_timer(ref)
        {:reply, :ok, %{state |
          active_keys: new_active,
          pending_shares: Map.delete(state.pending_shares, issuer_key_id),
          custodians_submitted: Map.delete(state.custodians_submitted, issuer_key_id),
          min_shares_cache: Map.delete(state.min_shares_cache, issuer_key_id)
        }}
    end
  end

  @impl true
  def handle_call({:dev_activate, issuer_key_id, private_key_der}, _from, state) do
    timer_ref = Process.send_after(self(), {:timeout, issuer_key_id}, state.timeout_ms)

    new_state = %{state |
      active_keys: Map.put(state.active_keys, issuer_key_id, %{secret: private_key_der, timer_ref: timer_ref})
    }

    {:reply, {:ok, :dev_activated}, new_state}
  end

  @impl true
  def handle_call({:get_active_key, issuer_key_id}, _from, state) do
    case Map.get(state.active_keys, issuer_key_id) do
      nil -> {:reply, {:error, :not_active}, state}
      %{secret: secret} -> {:reply, {:ok, secret}, state}
    end
  end

  @impl true
  def handle_info({:timeout, issuer_key_id}, state) do
    {:noreply, %{state |
      active_keys: Map.delete(state.active_keys, issuer_key_id),
      pending_shares: Map.delete(state.pending_shares, issuer_key_id),
      custodians_submitted: Map.delete(state.custodians_submitted, issuer_key_id),
      min_shares_cache: Map.delete(state.min_shares_cache, issuer_key_id)
    }}
  end
end
