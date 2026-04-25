defmodule PkiCaEngine.ActivationCeremony do
  @moduledoc """
  State-machine orchestrator for the "k custodians authenticate → lease granted"
  activation ceremony, separate from key generation.

  ## Flow

  1. Call `start/2` to open an `ActivationSession` for a given `issuer_key_id`.
     The session status begins as `"awaiting_custodians"`.

  2. Each custodian calls `submit_auth/4` with their name and auth token (the
     per-custodian password used during key generation).  The token is verified
     against the `ThresholdShare` ciphertext stored in Mnesia — correct decryption
     proves custody of the share.  Duplicate submissions from the same custodian
     are rejected.

  3. Once `length(authenticated_custodians) >= threshold_k`, `maybe_grant_lease/1`
     is called automatically and the session transitions to `"threshold_met"` and
     then `"lease_active"` after `KeyActivation.activate/4` succeeds.

  4. `cancel/2` can be called at any time before `"lease_active"` to abort the
     session.  This sets the status to `"cancelled"` and persists the record for
     audit purposes.

  ## Auth token format

  For software keystores the `auth_token` is the plaintext password the custodian
  submitted during key generation.  It is used directly with
  `ShareEncryption.decrypt_share/2`.  HSM-backed keystores will swap this for a
  Dispatcher session token in a later phase (E2.4).

  ## KeyActivation server

  `maybe_grant_lease/1` calls `KeyActivation.activate/4` on the server registered
  as `PkiCaEngine.KeyActivation` by default.  Override with the `:key_activation`
  option in `start/2` for tests.
  """

  alias PkiMnesia.{Repo}
  alias PkiMnesia.Structs.{ActivationSession, IssuerKey, ThresholdShare}
  alias PkiCaEngine.{KeyActivation, KeyStore.Dispatcher}
  alias PkiCaEngine.KeyCeremony.ShareEncryption

  # ---------------------------------------------------------------------------
  # Public API
  # ---------------------------------------------------------------------------

  @doc """
  Open a new activation session for `issuer_key_id`.

  ## Options

    * `:threshold_k` — minimum number of custodians required.  Defaults to the
      `min_shares` value found on the first `ThresholdShare` for this key.
    * `:threshold_n` — total custodian count.  Defaults to `total_shares` on the
      first share record.
    * `:ceremony_id` — optional link to a `KeyCeremony` record.
    * `:key_activation` — name or pid of the `KeyActivation` server to use.
      Defaults to `PkiCaEngine.KeyActivation`.

  Returns `{:ok, %ActivationSession{}}` or `{:error, reason}`.
  """
  @spec start(binary(), keyword()) :: {:ok, ActivationSession.t()} | {:error, term()}
  def start(issuer_key_id, opts \\ []) do
    with {:ok, key} <- load_issuer_key(issuer_key_id),
         :ok <- validate_activation_policy(key, opts),
         {:ok, {k, n}} <- resolve_threshold(issuer_key_id, opts) do
      session =
        ActivationSession.new(%{
          issuer_key_id: issuer_key_id,
          ceremony_id: opts[:ceremony_id],
          threshold_k: k,
          threshold_n: n
        })

      case Repo.insert(session) do
        {:ok, saved} -> {:ok, saved}
        {:error, reason} -> {:error, {:persist_failed, reason}}
      end
    end
  end

  @doc """
  Submit a custodian's auth token for `session_id`.

  For software keystores the `auth_token` is the custodian's plaintext password.

  Returns:
    * `{:ok, %ActivationSession{}}` — auth accepted; check `.status` to see if
      the threshold was met and a lease was granted.
    * `{:error, :session_not_found}` — no session with this id.
    * `{:error, :session_closed}` — session is no longer in `"awaiting_custodians"` state.
    * `{:error, :already_authenticated}` — this custodian already submitted in this session.
    * `{:error, :share_not_found}` — no `ThresholdShare` for this custodian / key combination.
    * `{:error, :authentication_failed}` — wrong auth token (decryption tag mismatch).
  """
  @spec submit_auth(binary(), String.t(), binary(), keyword()) ::
          {:ok, ActivationSession.t()} | {:ok, :lease_granted} | {:error, term()}
  def submit_auth(session_id, custodian_name, auth_token, opts \\ []) do
    with {:ok, session} <- fetch_open_session(session_id),
         :ok <- check_not_duplicate(session, custodian_name),
         {:ok, _share} <- verify_auth(session.issuer_key_id, custodian_name, auth_token) do
      entry = %{name: custodian_name, authenticated_at: DateTime.utc_now() |> DateTime.truncate(:second)}
      new_custodians = session.authenticated_custodians ++ [entry]
      new_tokens = (session.auth_tokens || []) ++ [auth_token]

      updated_session =
        session
        |> Map.put(:authenticated_custodians, new_custodians)
        |> Map.put(:auth_tokens, new_tokens)
        |> Map.put(:updated_at, DateTime.utc_now() |> DateTime.truncate(:second))

      case persist_session(updated_session) do
        {:ok, persisted} ->
          if length(new_custodians) >= persisted.threshold_k do
            # Pass the in-memory session (with auth_tokens) directly to
            # do_grant_lease so the tokens are never re-read from Mnesia
            # where they are deliberately not persisted (H2 fix).
            do_grant_lease(persisted, opts)
          else
            {:ok, persisted}
          end

        {:error, reason} ->
          {:error, {:persist_failed, reason}}
      end
    end
  end

  # After the H2 auth-token zeroing fix, auth_tokens are not persisted to
  # Mnesia. Calling this function externally re-reads auth_tokens: [] from
  # Mnesia and passes empty tokens to Dispatcher.authorize_session/2 —
  # silently failing for software keystores. Use submit_auth/4 instead;
  # it grants the lease automatically when threshold is met.
  @doc false
  @spec maybe_grant_lease(binary(), keyword()) ::
          {:ok, :lease_granted} | {:ok, :awaiting_more_custodians} | {:error, term()}
  def maybe_grant_lease(session_id, opts \\ []) do
    with {:ok, session} <- fetch_session(session_id) do
      cond do
        session.status == "lease_active" ->
          {:ok, :lease_granted}

        length(session.authenticated_custodians) < session.threshold_k ->
          {:ok, :awaiting_more_custodians}

        session.auth_tokens == [] ->
          {:error, :tokens_not_available_use_submit_auth}

        true ->
          do_grant_lease(session, opts)
      end
    end
  end

  @doc """
  Recover sessions that were stuck in `"threshold_met"` due to a crash
  between the first and second Mnesia write in `do_grant_lease/2`.

  Any `ActivationSession` with `status: "threshold_met"` whose `inserted_at`
  is more than 5 minutes ago is reverted to `"awaiting_custodians"` so
  custodians can re-authenticate on restart.  Sessions that have been in
  `"threshold_met"` for fewer than 5 minutes are left alone -- they may still
  have an in-flight grant in progress.

  Call this once on application boot, after Mnesia tables are available.

  Returns `{:ok, count}` where `count` is the number of sessions recovered.
  """
  @spec recover_stuck_sessions() :: {:ok, non_neg_integer()}
  def recover_stuck_sessions do
    cutoff = DateTime.add(DateTime.utc_now() |> DateTime.truncate(:second), -300, :second)

    {:ok, stuck} =
      Repo.where(ActivationSession, fn session ->
        session.status == "threshold_met" and
          DateTime.compare(session.inserted_at, cutoff) == :lt
      end)

    recovered =
      Enum.reduce(stuck, 0, fn session, count ->
        now = DateTime.utc_now() |> DateTime.truncate(:second)

        case Repo.update(session, %{
               status: "awaiting_custodians",
               updated_at: now
             }) do
          {:ok, _} ->
            count + 1

          {:error, reason} ->
            require Logger
            Logger.warning("[ActivationCeremony] recover_stuck_sessions: failed to revert \#{session.id}: \#{inspect(reason)}")
            count
        end
      end)

    {:ok, recovered}
  end

  @doc """
  Cancel the activation session.

  Returns `:ok` regardless of the previous status (idempotent cancel).
  """
  @spec cancel(binary(), String.t()) :: :ok
  def cancel(session_id, reason \\ "cancelled") do
    case fetch_session(session_id) do
      {:ok, session} ->
        now = DateTime.utc_now() |> DateTime.truncate(:second)

        updated =
          session
          |> Map.put(:status, "cancelled")
          |> Map.put(:completed_at, now)
          |> Map.put(:updated_at, now)

        _ = persist_session(updated)
        _ = reason  # stored for future audit; not persisted in this phase
        :ok

      {:error, _} ->
        :ok
    end
  end

  # ---------------------------------------------------------------------------
  # Private helpers
  # ---------------------------------------------------------------------------

  defp resolve_threshold(issuer_key_id, opts) do
    k = opts[:threshold_k]
    n = opts[:threshold_n]

    if not is_nil(k) and not is_nil(n) do
      {:ok, {k, n}}
    else
      # Derive from the first ThresholdShare for this key
      case Repo.get_all_by_index(ThresholdShare, :issuer_key_id, issuer_key_id) do
        {:ok, [share | _]} ->
          resolved_k = k || share.min_shares
          resolved_n = n || share.total_shares
          {:ok, {resolved_k, resolved_n}}

        {:ok, []} ->
          if not is_nil(k) and not is_nil(n) do
            {:ok, {k, n}}
          else
            {:error, :no_shares_found}
          end

        {:error, reason} ->
          {:error, {:share_lookup_failed, reason}}
      end
    end
  end

  defp fetch_session(session_id) do
    case Repo.get(ActivationSession, session_id) do
      {:ok, nil} -> {:error, :session_not_found}
      {:ok, session} -> {:ok, session}
      {:error, reason} -> {:error, {:lookup_failed, reason}}
    end
  end

  defp fetch_open_session(session_id) do
    with {:ok, session} <- fetch_session(session_id) do
      if session.status == "awaiting_custodians" do
        {:ok, session}
      else
        {:error, :session_closed}
      end
    end
  end

  defp check_not_duplicate(session, custodian_name) do
    already = Enum.any?(session.authenticated_custodians, fn e -> e.name == custodian_name end)
    if already, do: {:error, :already_authenticated}, else: :ok
  end

  defp verify_auth(issuer_key_id, custodian_name, auth_token) do
    case Repo.get_all_by_index(ThresholdShare, :issuer_key_id, issuer_key_id) do
      {:ok, shares} ->
        case Enum.find(shares, fn s -> s.custodian_name == custodian_name end) do
          nil ->
            {:error, :share_not_found}

          share ->
            case ShareEncryption.decrypt_share(share.encrypted_share, auth_token) do
              {:ok, _plaintext} -> {:ok, share}
              {:error, _} -> {:error, :authentication_failed}
            end
        end

      {:ok, []} ->
        {:error, :share_not_found}

      {:error, reason} ->
        {:error, {:share_lookup_failed, reason}}
    end
  end

  defp persist_session(session) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    updated = Map.put(session, :updated_at, now)

    # Never persist raw auth tokens — hold only in process memory for the
    # duration of the threshold-met → do_grant_lease call.
    case Repo.update(updated, %{
      status: updated.status,
      authenticated_custodians: updated.authenticated_custodians,
      auth_tokens: [],
      completed_at: updated.completed_at,
      updated_at: now
    }) do
      {:ok, saved} -> {:ok, Map.put(saved, :auth_tokens, updated.auth_tokens || [])}
      {:error, reason} -> {:error, reason}
    end
  end

  defp load_issuer_key(issuer_key_id) do
    case Repo.get(IssuerKey, issuer_key_id) do
      {:ok, nil} -> {:error, :issuer_key_not_found}
      {:ok, key} -> {:ok, key}
      {:error, reason} -> {:error, {:key_lookup_failed, reason}}
    end
  end

  # H5: root keys with a non-threshold key_mode cannot be activated at all.
  defp validate_activation_policy(%{key_role: "root", key_mode: mode}, _opts)
       when mode != "threshold",
       do: {:error, :root_requires_threshold}

  # H5: root keys must not be activated with a threshold_k lower than the
  # threshold recorded at ceremony time.
  defp validate_activation_policy(%{key_role: "root"} = key, opts) do
    supplied_k = Keyword.get(opts, :threshold_k)
    stored_k = key.threshold_config[:k] || key.threshold_config["k"]

    cond do
      supplied_k != nil and supplied_k < (stored_k || 2) ->
        {:error, :root_requires_threshold}

      true ->
        :ok
    end
  end

  defp validate_activation_policy(_key, _opts), do: :ok

  defp do_grant_lease(session, opts) do
    ka_server = opts[:key_activation] || KeyActivation

    # Mark threshold_met before attempting lease grant
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    transitioning =
      session
      |> Map.put(:status, "threshold_met")
      |> Map.put(:updated_at, now)

    {:ok, _} = persist_session(transitioning)

    custodian_names = Enum.map(session.authenticated_custodians, & &1.name)
    auth_tokens = session.auth_tokens || []

    result =
      with {:ok, handle} <- Dispatcher.authorize_session(session.issuer_key_id, auth_tokens) do
        KeyActivation.activate(ka_server, session.issuer_key_id, handle, custodian_names, opts)
      end

    case result do
      {:ok, _key_id} ->
        now2 = DateTime.utc_now() |> DateTime.truncate(:second)
        completed =
          session
          |> Map.put(:status, "lease_active")
          |> Map.put(:completed_at, now2)
          |> Map.put(:updated_at, now2)

        {:ok, _} = persist_session(completed)
        {:ok, :lease_granted}

      {:error, reason} ->
        now2 = DateTime.utc_now() |> DateTime.truncate(:second)
        failed =
          session
          |> Map.put(:status, "failed")
          |> Map.put(:completed_at, now2)
          |> Map.put(:updated_at, now2)

        {:ok, _} = persist_session(failed)
        {:error, {:lease_grant_failed, reason}}
    end
  end
end
