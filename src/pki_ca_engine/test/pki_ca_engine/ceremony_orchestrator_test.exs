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

  describe "execute_keygen/2 post-ceremony password_hash wipe" do
    # When a ceremony completes, the custodian password_hash has served its
    # accept-vs-execute verification purpose. The authoritative record is the
    # AES-GCM ciphertext in encrypted_share — the GCM tag authenticates the
    # submitted password at activation time, so a separate hash is dead
    # weight (and an offline-crackable artifact). Encrypt_and_commit wipes
    # password_hash atomically with the status flip to "active".

    test "wipes password_hash and flips status to active on success" do
      {:ok, {ceremony, _key, _shares, _participants, _transcript}} = create_test_ceremony()

      {:ok, _} = CeremonyOrchestrator.accept_share(ceremony.id, "Alice", "alice-pw")
      {:ok, _} = CeremonyOrchestrator.accept_share(ceremony.id, "Bob", "bob-pw")
      {:ok, _} = CeremonyOrchestrator.accept_share(ceremony.id, "Charlie", "charlie-pw")

      passwords = [{"Alice", "alice-pw"}, {"Bob", "bob-pw"}, {"Charlie", "charlie-pw"}]

      assert {:ok, _} = CeremonyOrchestrator.execute_keygen(ceremony.id, passwords)

      {:ok, shares_after} =
        PkiMnesia.Repo.get_all_by_index(PkiMnesia.Structs.ThresholdShare, :issuer_key_id, ceremony.issuer_key_id)

      assert length(shares_after) == 3

      for share <- shares_after do
        assert share.status == "active", "share #{share.custodian_name} should be active"
        assert share.encrypted_share != nil, "share #{share.custodian_name} should have encrypted_share"
        assert share.password_hash == nil,
               "share #{share.custodian_name} password_hash must be wiped post-ceremony, got: #{inspect(share.password_hash)}"
      end
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

  describe "execute_keygen/2 password verification" do
    # Regression tests for pre-landing review P1:
    # "custodian password must be verified against the stored hash before
    # encrypting the share". See TODOS.md for context.

    test "rejects when a custodian's password does not match the stored hash" do
      {:ok, {ceremony, _key, _shares, _participants, _transcript}} = create_test_ceremony()

      # All three custodians accept with their real passwords.
      {:ok, _} = CeremonyOrchestrator.accept_share(ceremony.id, "Alice", "alice-real")
      {:ok, _} = CeremonyOrchestrator.accept_share(ceremony.id, "Bob", "bob-real")
      {:ok, _} = CeremonyOrchestrator.accept_share(ceremony.id, "Charlie", "charlie-real")

      # Caller passes WRONG passwords for Alice and Bob, right for Charlie.
      wrong = [
        {"Alice", "attacker-picked"},
        {"Bob", "attacker-picked"},
        {"Charlie", "charlie-real"}
      ]

      assert {:error, {:custodian_password_mismatch, name}} =
               CeremonyOrchestrator.execute_keygen(ceremony.id, wrong)

      assert name in ["Alice", "Bob"]
    end

    test "rejects when a share was never accepted" do
      {:ok, {ceremony, _key, _shares, _participants, _transcript}} = create_test_ceremony()

      # Only two of three custodians accept.
      {:ok, _} = CeremonyOrchestrator.accept_share(ceremony.id, "Alice", "alice-real")
      {:ok, _} = CeremonyOrchestrator.accept_share(ceremony.id, "Bob", "bob-real")

      passwords = [
        {"Alice", "alice-real"},
        {"Bob", "bob-real"},
        {"Charlie", "charlie-any"}
      ]

      assert {:error, {:share_not_accepted, "Charlie"}} =
               CeremonyOrchestrator.execute_keygen(ceremony.id, passwords)
    end

    test "rejects when a custodian is missing from the password map" do
      {:ok, {ceremony, _key, _shares, _participants, _transcript}} = create_test_ceremony()

      {:ok, _} = CeremonyOrchestrator.accept_share(ceremony.id, "Alice", "alice-real")
      {:ok, _} = CeremonyOrchestrator.accept_share(ceremony.id, "Bob", "bob-real")
      {:ok, _} = CeremonyOrchestrator.accept_share(ceremony.id, "Charlie", "charlie-real")

      # Bob is missing from the password map.
      incomplete = [{"Alice", "alice-real"}, {"Charlie", "charlie-real"}]

      assert {:error, {:missing_password, "Bob"}} =
               CeremonyOrchestrator.execute_keygen(ceremony.id, incomplete)
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
