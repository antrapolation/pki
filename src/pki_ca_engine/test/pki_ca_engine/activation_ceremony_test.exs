defmodule PkiCaEngine.ActivationCeremonyTest do
  @moduledoc """
  Tests for ActivationCeremony — the k-of-n custodian authentication state
  machine that precedes key lease grant.
  """
  use ExUnit.Case, async: false

  alias PkiMnesia.{TestHelper, Repo}
  alias PkiMnesia.Structs.{ThresholdShare, ActivationSession}
  alias PkiCaEngine.{ActivationCeremony, KeyActivation}
  alias PkiCaEngine.KeyCeremony.ShareEncryption

  # ---------------------------------------------------------------------------
  # Test helpers
  # ---------------------------------------------------------------------------

  # Build and persist n encrypted ThresholdShare records for issuer_key_id.
  # Returns a list of {custodian_name, password} tuples.
  defp seed_shares(issuer_key_id, custodians, min_shares) do
    total = length(custodians)

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
end
