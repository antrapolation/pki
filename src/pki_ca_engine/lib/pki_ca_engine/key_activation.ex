defmodule PkiCaEngine.KeyActivation do
  @moduledoc """
  Day-to-day key activation via threshold share reconstruction.

  K custodians provide their shares (user_id + password), shares are decrypted
  from DB, and when threshold K is met the private key is reconstructed and
  held in memory with a configurable timeout.
  """
  use GenServer

  alias PkiCaEngine.{Repo, Schema.ThresholdShare}
  alias PkiCaEngine.KeyCeremony.ShareEncryption
  import Ecto.Query

  # ── Client API ────────────────────────────────────────────────

  def start_link(opts) do
    name = opts[:name] || __MODULE__
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc """
  Submit a custodian's share for key activation.

  Decrypts the share from DB using the custodian's password and accumulates it.
  Returns `{:ok, :share_accepted}` or `{:ok, :key_activated}` when threshold met.
  """
  def submit_share(server \\ __MODULE__, issuer_key_id, custodian_user_id, password) do
    GenServer.call(server, {:submit_share, issuer_key_id, custodian_user_id, password})
  end

  @doc "Returns true if the given issuer key is currently activated."
  def is_active?(server \\ __MODULE__, issuer_key_id) do
    GenServer.call(server, {:is_active, issuer_key_id})
  end

  @doc "Explicitly deactivate (wipe) an active key."
  def deactivate(server \\ __MODULE__, issuer_key_id) do
    GenServer.call(server, {:deactivate, issuer_key_id})
  end

  @doc "Retrieve the reconstructed secret for an active key."
  def get_active_key(server \\ __MODULE__, issuer_key_id) do
    GenServer.call(server, {:get_active_key, issuer_key_id})
  end

  # ── Server Callbacks ──────────────────────────────────────────

  @impl true
  def init(opts) do
    timeout_ms = opts[:timeout_ms] || 3_600_000

    {:ok,
     %{
       active_keys: %{},
       pending_shares: %{},
       custodians_submitted: %{},
       timeout_ms: timeout_ms
     }}
  end

  @impl true
  def handle_call({:submit_share, issuer_key_id, custodian_user_id, password}, _from, state) do
    # Check for duplicate submission
    submitted_set = Map.get(state.custodians_submitted, issuer_key_id, MapSet.new())

    if MapSet.member?(submitted_set, custodian_user_id) do
      {:reply, {:error, :already_submitted}, state}
    else
      # Fetch encrypted share from DB
      share_record =
        Repo.one(
          from ts in ThresholdShare,
            where: ts.issuer_key_id == ^issuer_key_id and ts.custodian_user_id == ^custodian_user_id
        )

      case share_record do
        nil ->
          {:reply, {:error, :share_not_found}, state}

        record ->
          case ShareEncryption.decrypt_share(record.encrypted_share, password) do
            {:error, :decryption_failed} ->
              {:reply, {:error, :decryption_failed}, state}

            {:ok, decrypted_share} ->
              # Track this custodian as submitted
              new_submitted =
                Map.put(
                  state.custodians_submitted,
                  issuer_key_id,
                  MapSet.put(submitted_set, custodian_user_id)
                )

              pending = Map.get(state.pending_shares, issuer_key_id, [])
              new_pending = [decrypted_share | pending]

              if length(new_pending) >= record.min_shares do
                # Threshold met - reconstruct secret
                case PkiCrypto.Shamir.recover(new_pending) do
                  {:ok, secret} ->
                    timer_ref = Process.send_after(self(), {:timeout, issuer_key_id}, state.timeout_ms)

                    new_state = %{
                      state
                      | active_keys:
                          Map.put(state.active_keys, issuer_key_id, %{
                            secret: secret,
                            timer_ref: timer_ref
                          }),
                        pending_shares: Map.delete(state.pending_shares, issuer_key_id),
                        custodians_submitted: new_submitted
                    }

                    {:reply, {:ok, :key_activated}, new_state}

                  {:error, reason} ->
                    {:reply, {:error, {:reconstruction_failed, reason}}, state}
                end
              else
                new_state = %{
                  state
                  | pending_shares: Map.put(state.pending_shares, issuer_key_id, new_pending),
                    custodians_submitted: new_submitted
                }

                {:reply, {:ok, :share_accepted}, new_state}
              end
          end
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
        {:reply, :ok, %{state | active_keys: new_active}}
    end
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
    new_active = Map.delete(state.active_keys, issuer_key_id)
    {:noreply, %{state | active_keys: new_active}}
  end
end
