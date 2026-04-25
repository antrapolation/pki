defmodule PkiCaEngine.ActivationCeremonyTest do
  @moduledoc """
  Tests for ActivationCeremony — the k-of-n custodian authentication state
  machine that precedes key lease grant.
  """
  use ExUnit.Case, async: false

  alias PkiMnesia.{TestHelper, Repo}
  alias PkiMnesia.Structs.{IssuerKey, ThresholdShare, ActivationSession}
  alias PkiCaEngine.{ActivationCeremony, KeyActivation}
  alias PkiCaEngine.KeyCeremony.ShareEncryption

  # ---------------------------------------------------------------------------
  # Test helpers
  # ---------------------------------------------------------------------------

  # Build and persist an IssuerKey + n encrypted ThresholdShare records for
  # issuer_key_id.  The Dispatcher.authorize_session call in do_grant_lease
  # requires the IssuerKey to be present in Mnesia so it can route to the
  # correct adapter.
  # Returns a list of {custodian_name, password} tuples.
  defp seed_shares(issuer_key_id, custodians, min_shares) do
    total = length(custodians)

    # Ensure an IssuerKey record exists so Dispatcher.authorize_session can
    # resolve the keystore_type for this key.
    key =
      IssuerKey.new(%{
        id: issuer_key_id,
        ca_instance_id: "ca-ceremony-test",
        algorithm: "ECC-P256",
        status: "active",
        keystore_type: :software
      })

    {:ok, _} = Repo.insert(key)

    custodians
    |> Enum.with_index(1)
    |> Enum.map(fn {{name, password}, idx} ->
      share_data = :crypto.strong_rand_bytes(32)
      {:ok, encrypted} = ShareEncryption.encrypt_share(share_data, password)

      record =
        ThresholdShare.new(%{
          issuer_key_id: issuer_key_id,
          custodian_name: name,
          share_index: idx,
          encrypted_share: encrypted,
          min_shares: min_shares,
          total_shares: total,
          status: "active"
        })

      {:ok, _} = Repo.insert(record)
      {name, password}
    end)
  end

  # ---------------------------------------------------------------------------
  # Setup
  # ---------------------------------------------------------------------------

  setup do
    dir = TestHelper.setup_mnesia()

    # Start a named KeyActivation server for each test
    ka_name = :"test_ka_#{System.unique_integer([:positive])}"
    {:ok, ka_pid} = KeyActivation.start_link(name: ka_name)

    on_exit(fn ->
      if Process.alive?(ka_pid), do: GenServer.stop(ka_pid)
      TestHelper.teardown_mnesia(dir)
    end)

    %{ka: ka_name}
  end

  # ---------------------------------------------------------------------------
  # Test 1: 2-of-3 ceremony — all three custodians submit → lease granted
  # ---------------------------------------------------------------------------

  test "2-of-3 ceremony: three custodians submit and lease is granted", %{ka: ka} do
    key_id = PkiMnesia.Id.generate()
    custodians = [{"Alice", "pw-alice"}, {"Bob", "pw-bob"}, {"Charlie", "pw-charlie"}]
    seed_shares(key_id, custodians, 2)

    {:ok, session} = ActivationCeremony.start(key_id, key_activation: ka)
    assert session.status == "awaiting_custodians"
    assert session.threshold_k == 2
    assert session.threshold_n == 3

    {:ok, s1} = ActivationCeremony.submit_auth(session.id, "Alice", "pw-alice", key_activation: ka)
    # 1 of 2 — still waiting
    assert s1.status == "awaiting_custodians"
    assert length(s1.authenticated_custodians) == 1

    # Second custodian meets the threshold
    assert {:ok, :lease_granted} =
             ActivationCeremony.submit_auth(session.id, "Bob", "pw-bob", key_activation: ka)

    # Lease should now be active in KeyActivation
    assert KeyActivation.is_active?(ka, key_id)

    # Confirm session persisted as lease_active
    {:ok, final_session} = Repo.get(ActivationSession, session.id)
    assert final_session.status == "lease_active"
    assert length(final_session.authenticated_custodians) == 2
    assert not is_nil(final_session.completed_at)
  end

  # ---------------------------------------------------------------------------
  # Test 2: 2-of-3 — only 1 custodian submits → status stays awaiting_custodians
  # ---------------------------------------------------------------------------

  test "2-of-3 ceremony: only one custodian submits → stays awaiting_custodians", %{ka: ka} do
    key_id = PkiMnesia.Id.generate()
    custodians = [{"Alice", "pw-alice"}, {"Bob", "pw-bob"}, {"Charlie", "pw-charlie"}]
    seed_shares(key_id, custodians, 2)

    {:ok, session} = ActivationCeremony.start(key_id, key_activation: ka)

    {:ok, updated} = ActivationCeremony.submit_auth(session.id, "Alice", "pw-alice", key_activation: ka)

    assert updated.status == "awaiting_custodians"
    assert length(updated.authenticated_custodians) == 1

    # Lease must NOT be active
    refute KeyActivation.is_active?(ka, key_id)

    # Confirm persisted state
    {:ok, persisted} = Repo.get(ActivationSession, session.id)
    assert persisted.status == "awaiting_custodians"
    assert is_nil(persisted.completed_at)
  end

  # ---------------------------------------------------------------------------
  # Test 3: Wrong auth token → {:error, :authentication_failed}, not counted
  # ---------------------------------------------------------------------------

  test "wrong auth token returns authentication_failed and custodian is not counted", %{ka: ka} do
    key_id = PkiMnesia.Id.generate()
    custodians = [{"Alice", "correct-password"}, {"Bob", "pw-bob"}]
    seed_shares(key_id, custodians, 2)

    {:ok, session} = ActivationCeremony.start(key_id, key_activation: ka)

    assert {:error, :authentication_failed} =
             ActivationCeremony.submit_auth(session.id, "Alice", "wrong-password", key_activation: ka)

    # Session should still be awaiting with zero authenticated custodians
    {:ok, persisted} = Repo.get(ActivationSession, session.id)
    assert persisted.status == "awaiting_custodians"
    assert persisted.authenticated_custodians == []

    refute KeyActivation.is_active?(ka, key_id)
  end

  # ---------------------------------------------------------------------------
  # Test 4: cancel/2 sets status to "cancelled"
  # ---------------------------------------------------------------------------

  test "cancel/2 sets session status to cancelled", %{ka: ka} do
    key_id = PkiMnesia.Id.generate()
    custodians = [{"Alice", "pw-alice"}, {"Bob", "pw-bob"}]
    seed_shares(key_id, custodians, 2)

    {:ok, session} = ActivationCeremony.start(key_id, key_activation: ka)

    # Submit one custodian so we have partial state
    {:ok, _} = ActivationCeremony.submit_auth(session.id, "Alice", "pw-alice", key_activation: ka)

    :ok = ActivationCeremony.cancel(session.id, "operator cancelled")

    {:ok, persisted} = Repo.get(ActivationSession, session.id)
    assert persisted.status == "cancelled"
    assert not is_nil(persisted.completed_at)

    # Submitting after cancel must return session_closed
    assert {:error, :session_closed} =
             ActivationCeremony.submit_auth(session.id, "Bob", "pw-bob", key_activation: ka)

    refute KeyActivation.is_active?(ka, key_id)
  end

  # ---------------------------------------------------------------------------
  # Test 5 (H5): start/2 with a root key + threshold_k: 1 → root_requires_threshold
  # ---------------------------------------------------------------------------

  test "H5: start/2 rejects threshold_k: 1 for a root key (threshold_config k=2)", %{ka: _ka} do
    key_id = PkiMnesia.Id.generate()

    root_key =
      IssuerKey.new(%{
        id: key_id,
        ca_instance_id: "ca-h5-test",
        algorithm: "ECC-P256",
        status: "active",
        keystore_type: :software,
        key_role: "root",
        key_mode: "threshold",
        threshold_config: %{k: 2, n: 3}
      })

    {:ok, _} = Repo.insert(root_key)

    assert {:error, :root_requires_threshold} =
             ActivationCeremony.start(key_id, threshold_k: 1, threshold_n: 3)
  end

  test "H5: start/2 rejects root key with non-threshold key_mode", %{ka: _ka} do
    key_id = PkiMnesia.Id.generate()

    root_key =
      IssuerKey.new(%{
        id: key_id,
        ca_instance_id: "ca-h5-mode-test",
        algorithm: "ECC-P256",
        status: "active",
        keystore_type: :software,
        key_role: "root",
        key_mode: "direct",
        threshold_config: %{k: 2, n: 3}
      })

    {:ok, _} = Repo.insert(root_key)

    assert {:error, :root_requires_threshold} =
             ActivationCeremony.start(key_id, threshold_k: 2, threshold_n: 3)
  end

  test "H5: start/2 allows root key with threshold_k equal to stored k", %{ka: _ka} do
    key_id = PkiMnesia.Id.generate()
    custodians = [{"Alice", "pw-alice"}, {"Bob", "pw-bob"}, {"Charlie", "pw-charlie"}]

    root_key =
      IssuerKey.new(%{
        id: key_id,
        ca_instance_id: "ca-h5-ok-test",
        algorithm: "ECC-P256",
        status: "active",
        keystore_type: :software,
        key_role: "root",
        key_mode: "threshold",
        threshold_config: %{k: 2, n: 3}
      })

    {:ok, _} = Repo.insert(root_key)

    # Seed shares so resolve_threshold can find them
    total = length(custodians)
    custodians
    |> Enum.with_index(1)
    |> Enum.each(fn {{name, password}, idx} ->
      share_data = :crypto.strong_rand_bytes(32)
      {:ok, encrypted} = ShareEncryption.encrypt_share(share_data, password)
      record = ThresholdShare.new(%{
        issuer_key_id: key_id,
        custodian_name: name,
        share_index: idx,
        encrypted_share: encrypted,
        min_shares: 2,
        total_shares: total,
        status: "active"
      })
      {:ok, _} = Repo.insert(record)
    end)

    assert {:ok, session} = ActivationCeremony.start(key_id, threshold_k: 2, threshold_n: 3)
    assert session.threshold_k == 2
  end

  # ---------------------------------------------------------------------------
  # Test 6: do_grant_lease failure path — Dispatcher error → session "failed"
  # ---------------------------------------------------------------------------

  test "do_grant_lease failure: Dispatcher.authorize_session error → session failed, subsequent submit returns session_closed",
       %{ka: ka} do
    key_id = PkiMnesia.Id.generate()

    # Insert an IssuerKey with an unsupported keystore_type to force
    # Dispatcher.authorize_session to return an error.
    bad_key =
      IssuerKey.new(%{
        id: key_id,
        ca_instance_id: "ca-grant-fail-test",
        algorithm: "ECC-P256",
        status: "active",
        keystore_type: :unknown_type
      })

    {:ok, _} = Repo.insert(bad_key)

    # Seed custodians with threshold k=1 so the first submit triggers grant
    custodians = [{"Alice", "pw-alice"}]
    total = length(custodians)
    custodians
    |> Enum.with_index(1)
    |> Enum.each(fn {{name, password}, idx} ->
      share_data = :crypto.strong_rand_bytes(32)
      {:ok, encrypted} = ShareEncryption.encrypt_share(share_data, password)
      record = ThresholdShare.new(%{
        issuer_key_id: key_id,
        custodian_name: name,
        share_index: idx,
        encrypted_share: encrypted,
        min_shares: 1,
        total_shares: total,
        status: "active"
      })
      {:ok, _} = Repo.insert(record)
    end)

    {:ok, session} =
      ActivationCeremony.start(key_id,
        threshold_k: 1,
        threshold_n: 1,
        key_activation: ka
      )

    # submit_auth triggers do_grant_lease which calls Dispatcher.authorize_session
    # — the unknown keystore_type causes an error
    assert {:error, _reason} =
             ActivationCeremony.submit_auth(session.id, "Alice", "pw-alice",
               key_activation: ka
             )

    # Session status must be "failed" in Mnesia
    {:ok, persisted} = Repo.get(ActivationSession, session.id)
    assert persisted.status == "failed"
    assert not is_nil(persisted.completed_at)

    # Subsequent submit on a failed session returns :session_closed
    assert {:error, :session_closed} =
             ActivationCeremony.submit_auth(session.id, "Alice", "pw-alice",
               key_activation: ka
             )
  end

  # ---------------------------------------------------------------------------
  # Test 7 (H2): auth_tokens must NOT be persisted to Mnesia
  # ---------------------------------------------------------------------------

  test "H2: auth_tokens are not persisted to Mnesia after custodian submit", %{ka: ka} do
    key_id = PkiMnesia.Id.generate()
    custodians = [{"Alice", "pw-alice"}, {"Bob", "pw-bob"}]
    seed_shares(key_id, custodians, 2)

    {:ok, session} = ActivationCeremony.start(key_id, key_activation: ka)

    # Alice submits — threshold not yet met (k=2)
    {:ok, _updated} = ActivationCeremony.submit_auth(session.id, "Alice", "pw-alice", key_activation: ka)

    # The persisted record in Mnesia must have auth_tokens == []
    {:ok, persisted} = Repo.get(ActivationSession, session.id)
    assert persisted.auth_tokens == []
  end

  # ---------------------------------------------------------------------------
  # Test 8 (M2): recover_stuck_sessions/0 reverts old threshold_met sessions
  # ---------------------------------------------------------------------------

  test "M2: recover_stuck_sessions/0 reverts sessions stuck in threshold_met > 5 min", %{ka: _ka} do
    key_id = PkiMnesia.Id.generate()
    custodians = [{"Alice", "pw-alice"}, {"Bob", "pw-bob"}]
    seed_shares(key_id, custodians, 2)

    # Seed a session that has been in threshold_met for 10 minutes
    ten_min_ago = DateTime.add(DateTime.utc_now() |> DateTime.truncate(:second), -600, :second)

    old_stuck =
      ActivationSession.new(%{
        issuer_key_id: key_id,
        threshold_k: 2,
        threshold_n: 2,
        status: "threshold_met",
        inserted_at: ten_min_ago,
        updated_at: ten_min_ago
      })

    {:ok, _} = Repo.insert(old_stuck)

    # Seed a session that has been in threshold_met for only 2 minutes (in-flight)
    two_min_ago = DateTime.add(DateTime.utc_now() |> DateTime.truncate(:second), -120, :second)

    recent_inflight =
      ActivationSession.new(%{
        issuer_key_id: key_id,
        threshold_k: 2,
        threshold_n: 2,
        status: "threshold_met",
        inserted_at: two_min_ago,
        updated_at: two_min_ago
      })

    {:ok, _} = Repo.insert(recent_inflight)

    # Run recovery -- only the old session (10 min) should be reverted
    assert {:ok, 1} = ActivationCeremony.recover_stuck_sessions()

    # Old session must be reverted to awaiting_custodians
    {:ok, recovered} = Repo.get(ActivationSession, old_stuck.id)
    assert recovered.status == "awaiting_custodians"

    # Recent in-flight session must remain untouched
    {:ok, still_stuck} = Repo.get(ActivationSession, recent_inflight.id)
    assert still_stuck.status == "threshold_met"
  end
end