defmodule PkiCaEngine.KeyActivation do
  @moduledoc """
  Day-to-day key activation via threshold share reconstruction.
  GenServer holds opaque session lease records in memory — it no longer stores
  raw private-key bytes directly in the activation map.

  ## Lease Model

  Each activated key is represented by a `lease_record`:

      %{
        handle:         term(),         # opaque — the reconstructed secret or HSM handle
        expires_at:     DateTime.t(),   # wall-clock expiry
        ops_remaining:  integer(),      # countdown; 0 means exhausted
        custodians:     [String.t()],   # names, for audit
        timer_ref:      reference()     # inactivity timer (cancel on deactivate)
      }

  Callers use `with_lease/2` to execute a function against the opaque handle,
  which atomically decrements `ops_remaining` and checks expiry.

  ## Lease Defaults

  Configurable via:

      config :pki_ca_engine, :lease_defaults,
        ttl_seconds: 4 * 3600,
        max_ops: 100

  ## Security Warning — Opaque Handle Exposure

  The handle (which for software keystores is still the reconstructed DER bytes)
  is now wrapped in a lease record rather than exposed directly.  The same
  cautions from the original module apply:

  - Do NOT expose this GenServer's pid or registered name outside the CA engine
    supervision tree.
  - Implement `format_status/2` to redact `active_leases` when needed.
  - Restrict `remsh` and Observer access in production.
  """
  use GenServer

  alias PkiMnesia.Repo
  alias PkiMnesia.Structs.ThresholdShare
  alias PkiCaEngine.KeyCeremony.ShareEncryption

  @unlimited_ops 1_000_000

  # -- Client API --

  def start_link(opts) do
    name = opts[:name] || __MODULE__
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc """
  Activate a key by storing an opaque `handle` (returned by the Dispatcher or
  reconstructed by the share ceremony) together with lease metadata.

  ## Options

    * `:ttl_seconds` — lease wall-clock lifetime in seconds.
      Defaults to `Application.get_env(:pki_ca_engine, :lease_defaults)[:ttl_seconds]`
      or 14 400 (4 h).
    * `:max_ops` — maximum number of `with_lease/2` executions before the lease
      is considered exhausted.
      Defaults to `Application.get_env(:pki_ca_engine, :lease_defaults)[:max_ops]`
      or 100.

  Returns `{:ok, key_id}` (the lease_id is the key_id itself) or
  `{:error, reason}`.
  """
  def activate(server \\ __MODULE__, key_id, handle, custodian_names, opts \\ []) do
    GenServer.call(server, {:activate, key_id, handle, custodian_names, opts})
  end

  @doc """
  Execute `fun.(handle)` against the currently active lease for `key_id`,
  decrement `ops_remaining`, and enforce expiry.

  Returns:
    * `{:ok, result}` — function executed successfully.
    * `{:error, :lease_expired}` — the wall-clock expiry has passed.
    * `{:error, :ops_exhausted}` — the ops counter has reached zero.
    * `{:error, :not_found}` — no active lease for this key_id.
  """
  def with_lease(server \\ __MODULE__, key_id, fun) do
    GenServer.call(server, {:with_lease, key_id, fun})
  end

  @doc """
  Return the current lease status for `key_id`.

  Always returns a map:

      %{
        active:              boolean,
        expires_in_seconds:  integer | nil,
        ops_remaining:       integer | nil
      }
  """
  def lease_status(server \\ __MODULE__, key_id) do
    GenServer.call(server, {:lease_status, key_id})
  end

  def is_active?(server \\ __MODULE__, issuer_key_id) do
    GenServer.call(server, {:is_active, issuer_key_id})
  end

  def deactivate(server \\ __MODULE__, issuer_key_id) do
    GenServer.call(server, {:deactivate, issuer_key_id})
  end

  @doc """
  **Deprecated** — use `with_lease/3` instead.

  Returns the opaque handle for the active lease. For software-keystore
  compatibility the handle IS the DER key bytes, so existing callers continue
  to work unchanged.
  """
  @deprecated "Use with_lease/3 to operate on the key handle"
  def get_active_key(server \\ __MODULE__, issuer_key_id) do
    case with_lease(server, issuer_key_id, fn handle -> handle end) do
      {:ok, handle} -> {:ok, handle}
      # Map :not_found → :not_active to preserve the original API contract
      {:error, :not_found} -> {:error, :not_active}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  **Deprecated** — submit a threshold share.  When the k-of-n threshold is
  reached, calls `activate/4` internally with `ops_remaining: :unlimited`
  (#{@unlimited_ops}) and returns the original `{:ok, :key_activated}` shape.
  """
  def submit_share(server \\ __MODULE__, issuer_key_id, custodian_name, password) do
    GenServer.call(server, {:submit_share, issuer_key_id, custodian_name, password})
  end

  @doc """
  Dev/test-only escape hatch that injects a private key directly into the
  activation cache, bypassing the threshold-share ceremony.

  Gated by the runtime flag `:pki_ca_engine, :allow_dev_activate` (default
  false). `PkiCaEngine.Application.start/2` hard-refuses to boot when the
  compile-time env is `:prod` and this flag is true, so a config mistake
  that enables the bypass in a production release is caught at startup.
  """
  def dev_activate(server \\ __MODULE__, issuer_key_id, private_key_der) do
    if Application.get_env(:pki_ca_engine, :allow_dev_activate, false) do
      GenServer.call(server, {:dev_activate, issuer_key_id, private_key_der})
    else
      {:error, :not_available_in_production}
    end
  end

  def count_active(server \\ __MODULE__) do
    GenServer.call(server, :count_active)
  end

  # -- Server Callbacks --

  @impl true
  def init(opts) do
    timeout_ms = opts[:timeout_ms] || 3_600_000

    {:ok, %{
      active_leases: %{},
      pending_shares: %{},
      custodians_submitted: %{},
      min_shares_cache: %{},
      timeout_ms: timeout_ms
    }}
  end

  @impl true
  def handle_call({:activate, key_id, handle, custodian_names, opts}, _from, state) do
    defaults = Application.get_env(:pki_ca_engine, :lease_defaults, [ttl_seconds: 4 * 3600, max_ops: 100])
    ttl_seconds = opts[:ttl_seconds] || defaults[:ttl_seconds] || 4 * 3600
    max_ops = opts[:max_ops] || defaults[:max_ops] || 100

    expires_at = DateTime.add(DateTime.utc_now(), ttl_seconds, :second)
    timer_ref = Process.send_after(self(), {:timeout, key_id}, ttl_seconds * 1_000)

    lease = %{
      handle: handle,
      expires_at: expires_at,
      ops_remaining: max_ops,
      custodians: custodian_names,
      timer_ref: timer_ref
    }

    new_state = %{state | active_leases: Map.put(state.active_leases, key_id, lease)}

    :telemetry.execute(
      [:pki_ca_engine, :key_activation, :lease],
      %{ops_remaining: max_ops, expires_in: ttl_seconds},
      %{key_id: key_id, event: :activated}
    )

    {:reply, {:ok, key_id}, new_state}
  end

  @impl true
  def handle_call({:with_lease, key_id, fun}, _from, state) do
    case Map.get(state.active_leases, key_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      lease ->
        now = DateTime.utc_now()

        cond do
          DateTime.compare(now, lease.expires_at) == :gt ->
            # Expired — evict and report
            new_state = evict_lease(state, key_id, :timer_expired)
            {:reply, {:error, :lease_expired}, new_state}

          lease.ops_remaining <= 0 ->
            # Ops exhausted — evict and mark session terminal
            new_state = evict_lease(state, key_id, :ops_exhausted)
            {:reply, {:error, :ops_exhausted}, new_state}

          true ->
            result =
              try do
                {:ok, fun.(lease.handle)}
              rescue
                e -> {:error, {:function_raised, Exception.message(e)}}
              catch
                kind, reason -> {:error, {:function_raised, {kind, reason}}}
              end

            case result do
              {:ok, value} ->
                new_ops_remaining = lease.ops_remaining - 1
                updated_lease = %{lease | ops_remaining: new_ops_remaining}
                new_state = %{state | active_leases: Map.put(state.active_leases, key_id, updated_lease)}

                :telemetry.execute(
                  [:pki_ca_engine, :key_activation, :lease],
                  %{ops_remaining: new_ops_remaining},
                  %{key_id: key_id, event: :used}
                )

                {:reply, {:ok, value}, new_state}

              {:error, _} = err ->
                {:reply, err, state}
            end
        end
    end
  end

  @impl true
  def handle_call({:lease_status, key_id}, _from, state) do
    case Map.get(state.active_leases, key_id) do
      nil ->
        {:reply, %{active: false, expires_in_seconds: nil, ops_remaining: nil}, state}

      lease ->
        now = DateTime.utc_now()
        diff = DateTime.diff(lease.expires_at, now, :second)

        if diff <= 0 or lease.ops_remaining <= 0 do
          {:reply, %{active: false, expires_in_seconds: max(diff, 0), ops_remaining: lease.ops_remaining}, state}
        else
          {:reply, %{active: true, expires_in_seconds: diff, ops_remaining: lease.ops_remaining}, state}
        end
    end
  end

  @impl true
  def handle_call({:is_active, issuer_key_id}, _from, state) do
    active =
      case Map.get(state.active_leases, issuer_key_id) do
        nil -> false
        lease ->
          now = DateTime.utc_now()
          DateTime.compare(now, lease.expires_at) != :gt and lease.ops_remaining > 0
      end

    {:reply, active, state}
  end

  @impl true
  def handle_call({:deactivate, issuer_key_id}, _from, state) do
    case Map.pop(state.active_leases, issuer_key_id) do
      {nil, _} ->
        {:reply, {:error, :not_active}, state}

      {%{timer_ref: ref}, new_active} ->
        Process.cancel_timer(ref)
        {:reply, :ok, %{state |
          active_leases: new_active,
          pending_shares: Map.delete(state.pending_shares, issuer_key_id),
          custodians_submitted: Map.delete(state.custodians_submitted, issuer_key_id),
          min_shares_cache: Map.delete(state.min_shares_cache, issuer_key_id)
        }}
    end
  end

  @impl true
  def handle_call({:submit_share, issuer_key_id, custodian_name, password}, _from, state) do
    submitted_set = Map.get(state.custodians_submitted, issuer_key_id, MapSet.new())

    if MapSet.member?(submitted_set, custodian_name) do
      {:reply, {:error, :already_submitted}, state}
    else
      # Look up shares from Mnesia by issuer_key_id (indexed), then filter by custodian_name
      case Repo.get_all_by_index(ThresholdShare, :issuer_key_id, issuer_key_id) do
        {:ok, []} ->
          {:reply, {:error, :share_not_found}, state}

        {:ok, shares} ->
          case Enum.find(shares, fn s -> s.custodian_name == custodian_name end) do
            nil ->
              {:reply, {:error, :share_not_found}, state}

            record ->
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
                        # Route through activate/4 with unlimited ops (shim behaviour)
                        defaults = Application.get_env(:pki_ca_engine, :lease_defaults, [ttl_seconds: 4 * 3600, max_ops: 100])
                        ttl_seconds = defaults[:ttl_seconds] || 4 * 3600
                        expires_at = DateTime.add(DateTime.utc_now(), ttl_seconds, :second)
                        timer_ref = Process.send_after(self(), {:timeout, issuer_key_id}, ttl_seconds * 1_000)

                        lease = %{
                          handle: secret,
                          expires_at: expires_at,
                          ops_remaining: @unlimited_ops,
                          custodians: [custodian_name],
                          timer_ref: timer_ref
                        }

                        new_state = %{state |
                          active_leases: Map.put(state.active_leases, issuer_key_id, lease),
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
          end

        {:error, reason} ->
          {:reply, {:error, {:share_lookup_failed, reason}}, state}
      end
    end
  end

  @impl true
  def handle_call({:dev_activate, issuer_key_id, private_key_der}, _from, state) do
    defaults = Application.get_env(:pki_ca_engine, :lease_defaults, [ttl_seconds: 4 * 3600, max_ops: 100])
    ttl_seconds = defaults[:ttl_seconds] || 4 * 3600
    expires_at = DateTime.add(DateTime.utc_now(), ttl_seconds, :second)
    timer_ref = Process.send_after(self(), {:timeout, issuer_key_id}, state.timeout_ms)

    lease = %{
      handle: private_key_der,
      expires_at: expires_at,
      ops_remaining: @unlimited_ops,
      custodians: ["dev"],
      timer_ref: timer_ref
    }

    new_state = %{state | active_leases: Map.put(state.active_leases, issuer_key_id, lease)}
    {:reply, {:ok, :dev_activated}, new_state}
  end

  @impl true
  def handle_call(:count_active, _from, state) do
    {:reply, map_size(state.active_leases), state}
  end

  @impl true
  def handle_info({:timeout, issuer_key_id}, state) do
    {:noreply, evict_lease(state, issuer_key_id, :timer_expired)}
  end

  # -- Private helpers --

  defp evict_lease(state, key_id, reason) do
    :telemetry.execute(
      [:pki_ca_engine, :key_activation, :lease],
      %{ops_remaining: 0, expires_in: 0},
      %{key_id: key_id, event: :expired}
    )

    # Update corresponding ActivationSession(s) in Mnesia to a terminal status
    # so auditors can query the lifecycle of every session. Spawned to avoid
    # blocking the GenServer message loop.
    terminal_status = if reason == :ops_exhausted, do: "exhausted", else: "expired"

    :erlang.spawn(fn ->
      case Repo.get_all_by_index(PkiMnesia.Structs.ActivationSession, :issuer_key_id, key_id) do
        {:ok, sessions} ->
          now = DateTime.utc_now() |> DateTime.truncate(:second)

          Enum.each(sessions, fn s ->
            if s.status == "lease_active" do
              Repo.update(s, %{status: terminal_status, completed_at: now, updated_at: now})
            end
          end)

        _ ->
          :ok
      end
    end)

    %{state |
      active_leases: Map.delete(state.active_leases, key_id),
      pending_shares: Map.delete(state.pending_shares, key_id),
      custodians_submitted: Map.delete(state.custodians_submitted, key_id),
      min_shares_cache: Map.delete(state.min_shares_cache, key_id)
    }
  end

  @impl true
  def format_status(status) do
    Map.update(status, :state, status[:state], fn state ->
      redacted =
        Map.new(state.active_leases, fn {key_id, lease} ->
          {key_id, %{lease | handle: :redacted}}
        end)

      %{state | active_leases: redacted}
    end)
  end
end
