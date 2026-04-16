defmodule PkiCaEngine.CeremonyOrchestratorTest do
  @moduledoc """
  Tests for the CeremonyOrchestrator module against Mnesia.
  Tests ceremony initiation, identity verification, and share acceptance.
  """
  use ExUnit.Case, async: false

  alias PkiMnesia.TestHelper
  alias PkiCaEngine.CeremonyOrchestrator

  setup do
    dir = TestHelper.setup_mnesia()

    on_exit(fn ->
      TestHelper.teardown_mnesia(dir)
    end)

    :ok
  end

  describe "initiate/2" do
    test "creates ceremony with all required records" do
      params = %{
        algorithm: "ECC-P256",
        threshold_k: 2,
        threshold_n: 3,
        custodian_names: ["Alice", "Bob", "Charlie"],
        auditor_name: "Dave",
        is_root: true,
        ceremony_mode: :full,
        initiated_by: "Admin",
        key_alias: "test-root-key",
        subject_dn: "/CN=Test Root CA"
      }

      assert {:ok, {ceremony, key, shares, participants, transcript}} =
        CeremonyOrchestrator.initiate("ca-1", params)

      assert ceremony.algorithm == "ECC-P256"
      assert ceremony.threshold_k == 2
      assert ceremony.threshold_n == 3
      assert ceremony.status == "preparing"

      assert key.algorithm == "ECC-P256"
      assert key.status == "pending"
      assert key.is_root == true

      assert length(shares) == 3
      assert length(participants) == 4  # 3 custodians + 1 auditor

      assert length(transcript.entries) == 1
      [entry] = transcript.entries
      assert entry.action == "ceremony_initiated"
    end

    test "rejects invalid threshold" do
      params = %{
        algorithm: "ECC-P256",
        threshold_k: 5,
        threshold_n: 3,
        custodian_names: ["Alice", "Bob", "Charlie"],
        auditor_name: "Dave",
        is_root: true,
        ceremony_mode: :full,
        initiated_by: "Admin"
      }

      assert {:error, :invalid_threshold} = CeremonyOrchestrator.initiate("ca-1", params)
    end

    test "rejects root CA with simplified mode" do
      params = %{
        algorithm: "ECC-P256",
        threshold_k: 2,
        threshold_n: 3,
        custodian_names: ["Alice", "Bob", "Charlie"],
        auditor_name: "Dave",
        is_root: true,
        ceremony_mode: :simplified,
        initiated_by: "Admin"
      }

      assert {:error, :root_ca_requires_full_ceremony} = CeremonyOrchestrator.initiate("ca-1", params)
    end

    test "rejects mismatched participant count" do
      params = %{
        algorithm: "ECC-P256",
        threshold_k: 2,
        threshold_n: 3,
        custodian_names: ["Alice", "Bob"],  # only 2, but n=3
        auditor_name: "Dave",
        is_root: true,
        ceremony_mode: :full,
        initiated_by: "Admin"
      }

      assert {:error, :participant_count_mismatch} = CeremonyOrchestrator.initiate("ca-1", params)
    end
  end

  describe "verify_identity/3" do
    test "marks a custodian as identity-verified" do
      {:ok, {ceremony, _key, _shares, _participants, _transcript}} = create_test_ceremony()

      assert {:ok, updated} = CeremonyOrchestrator.verify_identity(ceremony.id, "Alice", "Dave")
      assert updated.identity_verified_by == "Dave"
      assert updated.identity_verified_at != nil
    end

    test "returns error for unknown custodian" do
      {:ok, {ceremony, _key, _shares, _participants, _transcript}} = create_test_ceremony()

      assert {:error, :participant_not_found} = CeremonyOrchestrator.verify_identity(ceremony.id, "Unknown", "Dave")
    end
  end

  describe "accept_share/3" do
    test "accepts a custodian's share with password" do
      {:ok, {ceremony, _key, _shares, _participants, _transcript}} = create_test_ceremony()

      assert {:ok, updated_share} = CeremonyOrchestrator.accept_share(ceremony.id, "Alice", "password123")
      assert updated_share.status == "accepted"
      assert updated_share.password_hash != nil
    end
  end

  describe "check_readiness/1" do
    test "returns :waiting when not all verified and accepted" do
      {:ok, {ceremony, _key, _shares, _participants, _transcript}} = create_test_ceremony()

      assert :waiting = CeremonyOrchestrator.check_readiness(ceremony.id)
    end
  end

  describe "get_transcript/1" do
    test "returns transcript for existing ceremony" do
      {:ok, {ceremony, _key, _shares, _participants, _transcript}} = create_test_ceremony()

      assert {:ok, transcript} = CeremonyOrchestrator.get_transcript(ceremony.id)
      assert length(transcript.entries) >= 1
    end

    test "returns error for non-existent ceremony" do
      assert {:error, :not_found} = CeremonyOrchestrator.get_transcript("nonexistent")
    end
  end

  describe "list_participants/1" do
    test "returns all participants for a ceremony" do
      {:ok, {ceremony, _key, _shares, _participants, _transcript}} = create_test_ceremony()

      assert {:ok, participants} = CeremonyOrchestrator.list_participants(ceremony.id)
      assert length(participants) == 4  # 3 custodians + 1 auditor
    end
  end

  # Helper to create a standard test ceremony
  defp create_test_ceremony do
    params = %{
      algorithm: "ECC-P256",
      threshold_k: 2,
      threshold_n: 3,
      custodian_names: ["Alice", "Bob", "Charlie"],
      auditor_name: "Dave",
      is_root: true,
      ceremony_mode: :full,
      initiated_by: "Admin",
      key_alias: "test-key",
      subject_dn: "/CN=Test CA"
    }

    CeremonyOrchestrator.initiate("ca-test", params)
  end
end
