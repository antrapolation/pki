defmodule PkiCaEngine.AuditorPreconditionTest do
  @moduledoc """
  Tests for E1.6: auditor presence enforcement as ceremony pre-condition.

  Covers:
    1. No auditor_user_id → ceremony initiates normally (backward compat).
    2. auditor_user_id pointing to non-existent or non-auditor user → {:error, :auditor_required}.
    3. Valid auditor user → ceremony status is "awaiting_auditor_acceptance".
  """
  use ExUnit.Case, async: false

  alias PkiMnesia.TestHelper
  alias PkiMnesia.{Repo, Structs.PortalUser}
  alias PkiCaEngine.CeremonyOrchestrator

  setup do
    dir = TestHelper.setup_mnesia()

    on_exit(fn ->
      TestHelper.teardown_mnesia(dir)
    end)

    :ok
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp base_params do
    %{
      algorithm: "ECC-P256",
      threshold_k: 2,
      threshold_n: 3,
      custodian_names: ["Alice", "Bob", "Charlie"],
      auditor_name: "External Dave",
      is_root: true,
      ceremony_mode: :full,
      initiated_by: "Admin",
      key_alias: "test-key-e1.6",
      subject_dn: "/CN=Test CA E1.6"
    }
  end

  defp create_portal_user(role) do
    user = PortalUser.new(%{
      username: "testauditor_#{:erlang.unique_integer([:positive])}",
      display_name: "Test Auditor",
      email: "auditor@test.local",
      role: role,
      status: "active"
    })

    {:ok, _} = Repo.insert(user)
    user
  end

  # ---------------------------------------------------------------------------
  # Test 1: No auditor_user_id → backward compat, ceremony initiates normally
  # ---------------------------------------------------------------------------

  describe "initiate/2 without auditor_user_id" do
    test "ceremony status is 'preparing' (single-session external-auditor flow)" do
      params = base_params()

      assert {:ok, {ceremony, _key, _shares, _participants, _transcript}} =
               CeremonyOrchestrator.initiate("ca-e1.6-compat", params)

      assert ceremony.status == "preparing",
             "Expected 'preparing' for external-auditor flow, got: #{ceremony.status}"
    end

    test "auditor_name is still recorded as a participant" do
      params = base_params()

      {:ok, {ceremony, _key, _shares, participants, _transcript}} =
        CeremonyOrchestrator.initiate("ca-e1.6-compat-2", params)

      auditor_participant = Enum.find(participants, fn p -> p.role == :auditor end)
      assert auditor_participant != nil
      assert auditor_participant.name == "External Dave"
    end
  end

  # ---------------------------------------------------------------------------
  # Test 2: auditor_user_id pointing to non-existent or non-auditor user
  # ---------------------------------------------------------------------------

  describe "initiate/2 with invalid auditor_user_id" do
    test "non-existent auditor_user_id returns {:error, :auditor_required}" do
      params = Map.put(base_params(), :auditor_user_id, "nonexistent-user-id-abc123")

      assert {:error, :auditor_required} =
               CeremonyOrchestrator.initiate("ca-e1.6-nouser", params)
    end

    test "auditor_user_id pointing to a user with wrong role (ca_admin) returns {:error, :auditor_required}" do
      user = create_portal_user(:ca_admin)
      params = Map.put(base_params(), :auditor_user_id, user.id)

      assert {:error, :auditor_required} =
               CeremonyOrchestrator.initiate("ca-e1.6-wrongrole", params)
    end

    test "auditor_user_id pointing to a key_manager user returns {:error, :auditor_required}" do
      user = create_portal_user(:key_manager)
      params = Map.put(base_params(), :auditor_user_id, user.id)

      assert {:error, :auditor_required} =
               CeremonyOrchestrator.initiate("ca-e1.6-km", params)
    end
  end

  # ---------------------------------------------------------------------------
  # Test 3: Valid auditor user → ceremony status "awaiting_auditor_acceptance"
  # ---------------------------------------------------------------------------

  describe "initiate/2 with valid auditor_user_id" do
    test "ceremony is created with status 'awaiting_auditor_acceptance'" do
      user = create_portal_user(:auditor)
      params = Map.put(base_params(), :auditor_user_id, user.id)

      assert {:ok, {ceremony, _key, _shares, _participants, _transcript}} =
               CeremonyOrchestrator.initiate("ca-e1.6-valid", params)

      assert ceremony.status == "awaiting_auditor_acceptance",
             "Expected 'awaiting_auditor_acceptance', got: #{ceremony.status}"
    end

    test "auditor_user_id is stored in ceremony domain_info" do
      user = create_portal_user(:auditor)
      params = Map.put(base_params(), :auditor_user_id, user.id)

      {:ok, {ceremony, _key, _shares, _participants, _transcript}} =
        CeremonyOrchestrator.initiate("ca-e1.6-domain", params)

      assert ceremony.domain_info["auditor_user_id"] == user.id
    end

    test "transcript records auditor_pre_registered event" do
      user = create_portal_user(:auditor)
      params = Map.put(base_params(), :auditor_user_id, user.id)

      {:ok, {ceremony, _key, _shares, _participants, _transcript}} =
        CeremonyOrchestrator.initiate("ca-e1.6-transcript", params)

      {:ok, transcript} = CeremonyOrchestrator.get_transcript(ceremony.id)
      actions = Enum.map(transcript.entries, fn e -> e["action"] || e[:action] end)
      assert "auditor_pre_registered" in actions,
             "Expected auditor_pre_registered in transcript, got: #{inspect(actions)}"
    end

    test "accept_auditor_witness/2 transitions ceremony to 'preparing'" do
      user = create_portal_user(:auditor)
      params = Map.put(base_params(), :auditor_user_id, user.id)

      {:ok, {ceremony, _key, _shares, _participants, _transcript}} =
        CeremonyOrchestrator.initiate("ca-e1.6-accept", params)

      assert ceremony.status == "awaiting_auditor_acceptance"

      assert {:ok, updated} = CeremonyOrchestrator.accept_auditor_witness(ceremony.id, user.id)
      assert updated.status == "preparing"
    end

    test "accept_auditor_witness/2 appends auditor_accepted transcript event" do
      user = create_portal_user(:auditor)
      params = Map.put(base_params(), :auditor_user_id, user.id)

      {:ok, {ceremony, _key, _shares, _participants, _transcript}} =
        CeremonyOrchestrator.initiate("ca-e1.6-accept-transcript", params)

      {:ok, _} = CeremonyOrchestrator.accept_auditor_witness(ceremony.id, user.id)

      {:ok, transcript} = CeremonyOrchestrator.get_transcript(ceremony.id)
      actions = Enum.map(transcript.entries, fn e -> e["action"] || e[:action] end)
      assert "auditor_accepted" in actions,
             "Expected auditor_accepted in transcript, got: #{inspect(actions)}"
    end

    test "accept_auditor_witness/2 with non-auditor user returns {:error, :auditor_required}" do
      user = create_portal_user(:auditor)
      wrong_user = create_portal_user(:ca_admin)
      params = Map.put(base_params(), :auditor_user_id, user.id)

      {:ok, {ceremony, _key, _shares, _participants, _transcript}} =
        CeremonyOrchestrator.initiate("ca-e1.6-accept-wrong", params)

      assert {:error, :auditor_required} =
               CeremonyOrchestrator.accept_auditor_witness(ceremony.id, wrong_user.id)
    end

    test "accept_auditor_witness/2 on already-preparing ceremony returns {:error, :invalid_ceremony_status}" do
      # A ceremony without auditor_user_id starts in "preparing"
      user = create_portal_user(:auditor)
      params = base_params()

      {:ok, {ceremony, _key, _shares, _participants, _transcript}} =
        CeremonyOrchestrator.initiate("ca-e1.6-accept-status", params)

      assert {:error, :invalid_ceremony_status} =
               CeremonyOrchestrator.accept_auditor_witness(ceremony.id, user.id)
    end
  end
end
