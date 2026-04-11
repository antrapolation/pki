defmodule PkiCaEngine.CeremonyOrchestratorTest do
  @moduledoc """
  Integration tests for the CeremonyOrchestrator module.
  Tests multi-participant ceremony flow: initiate → accept shares → attest → keygen.
  Requires database (uses DataCase with SQL Sandbox).
  """
  use PkiCaEngine.DataCase, async: false

  alias PkiCaEngine.CeremonyOrchestrator
  alias PkiCaEngine.Schema.{CaInstance, Keystore, KeyCeremony, ThresholdShare, CeremonyAttestation}

  setup do
    # Create a CA instance and software keystore
    {:ok, ca} = Repo.insert(CaInstance.changeset(%CaInstance{}, %{name: "test-ca-#{System.unique_integer([:positive])}", created_by: "test"}))
    {:ok, keystore} = Repo.insert(Keystore.changeset(%Keystore{}, %{ca_instance_id: ca.id, type: "software"}))

    km1 = Uniq.UUID.uuid7()
    km2 = Uniq.UUID.uuid7()
    km3 = Uniq.UUID.uuid7()
    auditor = Uniq.UUID.uuid7()

    %{
      ca: ca,
      keystore: keystore,
      tenant_id: nil,
      custodian_ids: [km1, km2, km3],
      km1: km1, km2: km2, km3: km3,
      auditor_id: auditor
    }
  end

  defp initiate_params(ctx, overrides \\ %{}) do
    Map.merge(%{
      algorithm: "ECC-P256",
      keystore_id: ctx.keystore.id,
      threshold_k: 2,
      threshold_n: 3,
      initiated_by: Uniq.UUID.uuid7(),
      custodian_user_ids: ctx.custodian_ids,
      auditor_user_id: ctx.auditor_id,
      time_window_hours: 24,
      domain_info: %{"is_root" => true, "subject_dn" => "/CN=Test Root CA"},
      is_root: true
    }, overrides)
  end

  describe "initiate/3" do
    test "creates ceremony, issuer key, and placeholder shares", ctx do
      params = initiate_params(ctx)
      {:ok, {ceremony, issuer_key, shares}} = CeremonyOrchestrator.initiate(ctx.tenant_id, ctx.ca.id, params)

      assert ceremony.status == "preparing"
      assert ceremony.algorithm == "ECC-P256"
      assert ceremony.threshold_k == 2
      assert ceremony.threshold_n == 3
      assert ceremony.auditor_user_id == ctx.auditor_id
      assert ceremony.time_window_hours == 24
      assert ceremony.window_expires_at != nil

      assert issuer_key.algorithm == "ECC-P256"
      assert issuer_key.status == "pending"

      assert length(shares) == 3
      Enum.each(shares, fn share ->
        assert share.status == "pending"
        assert share.encrypted_share == nil
        assert share.key_label == nil
      end)
    end

    test "rejects invalid threshold k < 2", ctx do
      params = initiate_params(ctx, %{threshold_k: 1})
      assert {:error, :invalid_threshold} = CeremonyOrchestrator.initiate(ctx.tenant_id, ctx.ca.id, params)
    end

    test "rejects k > n", ctx do
      params = initiate_params(ctx, %{threshold_k: 4, threshold_n: 3})
      assert {:error, :invalid_threshold} = CeremonyOrchestrator.initiate(ctx.tenant_id, ctx.ca.id, params)
    end

    test "rejects participant count mismatch", ctx do
      params = initiate_params(ctx, %{custodian_user_ids: [ctx.km1, ctx.km2], threshold_n: 3, threshold_k: 2})
      assert {:error, :participant_count_mismatch} = CeremonyOrchestrator.initiate(ctx.tenant_id, ctx.ca.id, params)
    end

    test "stores participants in ceremony record", ctx do
      params = initiate_params(ctx)
      {:ok, {ceremony, _, _}} = CeremonyOrchestrator.initiate(ctx.tenant_id, ctx.ca.id, params)

      participants = ceremony.participants
      custodians = participants["custodians"] || participants[:custodians]
      auditor = participants["auditor"] || participants[:auditor]
      assert custodians == ctx.custodian_ids
      assert auditor == ctx.auditor_id
    end
  end

  describe "accept_share/4" do
    test "marks share as accepted with key label", ctx do
      params = initiate_params(ctx)
      {:ok, {ceremony, _, _}} = CeremonyOrchestrator.initiate(ctx.tenant_id, ctx.ca.id, params)

      {:ok, share} = CeremonyOrchestrator.accept_share(ctx.tenant_id, ceremony.id, ctx.km1, "alice-key-2026")

      assert share.status == "accepted"
      assert share.key_label == "alice-key-2026"
      assert share.accepted_at != nil
    end

    test "rejects share from non-assigned user", ctx do
      params = initiate_params(ctx)
      {:ok, {ceremony, _, _}} = CeremonyOrchestrator.initiate(ctx.tenant_id, ctx.ca.id, params)

      assert {:error, :share_not_found} = CeremonyOrchestrator.accept_share(ctx.tenant_id, ceremony.id, Uniq.UUID.uuid7(), "label")
    end

    test "rejects acceptance when ceremony is not preparing", ctx do
      params = initiate_params(ctx)
      {:ok, {ceremony, _, _}} = CeremonyOrchestrator.initiate(ctx.tenant_id, ctx.ca.id, params)

      # Manually set status to completed
      ceremony |> Ecto.Changeset.change(%{status: "completed"}) |> Repo.update!()

      assert {:error, :invalid_ceremony_status} = CeremonyOrchestrator.accept_share(ctx.tenant_id, ceremony.id, ctx.km1, "label")
    end
  end

  describe "attest/5" do
    test "creates attestation record", ctx do
      params = initiate_params(ctx)
      {:ok, {ceremony, _, _}} = CeremonyOrchestrator.initiate(ctx.tenant_id, ctx.ca.id, params)

      {:ok, attestation} = CeremonyOrchestrator.attest(ctx.tenant_id, ceremony.id, ctx.auditor_id, "preparation", %{note: "witnessed"})

      assert attestation.phase == "preparation"
      assert attestation.auditor_user_id == ctx.auditor_id
      assert attestation.attested_at != nil
      assert (attestation.details["note"] || attestation.details[:note]) == "witnessed"
    end

    test "rejects attestation from non-assigned auditor", ctx do
      params = initiate_params(ctx)
      {:ok, {ceremony, _, _}} = CeremonyOrchestrator.initiate(ctx.tenant_id, ctx.ca.id, params)

      assert {:error, :not_assigned_auditor} = CeremonyOrchestrator.attest(ctx.tenant_id, ceremony.id, "wrong-auditor", "preparation")
    end

    test "rejects duplicate attestation for same phase", ctx do
      params = initiate_params(ctx)
      {:ok, {ceremony, _, _}} = CeremonyOrchestrator.initiate(ctx.tenant_id, ctx.ca.id, params)

      {:ok, _} = CeremonyOrchestrator.attest(ctx.tenant_id, ceremony.id, ctx.auditor_id, "preparation")
      assert {:error, _} = CeremonyOrchestrator.attest(ctx.tenant_id, ceremony.id, ctx.auditor_id, "preparation")
    end
  end

  describe "check_readiness/2" do
    test "returns :waiting when not all custodians accepted", ctx do
      params = initiate_params(ctx)
      {:ok, {ceremony, _, _}} = CeremonyOrchestrator.initiate(ctx.tenant_id, ctx.ca.id, params)

      # Accept only 2 of 3
      CeremonyOrchestrator.accept_share(ctx.tenant_id, ceremony.id, ctx.km1, "key1")
      CeremonyOrchestrator.accept_share(ctx.tenant_id, ceremony.id, ctx.km2, "key2")

      assert :waiting = CeremonyOrchestrator.check_readiness(ctx.tenant_id, ceremony.id)
    end

    test "returns :waiting when all accepted but no attestation", ctx do
      params = initiate_params(ctx)
      {:ok, {ceremony, _, _}} = CeremonyOrchestrator.initiate(ctx.tenant_id, ctx.ca.id, params)

      CeremonyOrchestrator.accept_share(ctx.tenant_id, ceremony.id, ctx.km1, "key1")
      CeremonyOrchestrator.accept_share(ctx.tenant_id, ceremony.id, ctx.km2, "key2")
      CeremonyOrchestrator.accept_share(ctx.tenant_id, ceremony.id, ctx.km3, "key3")

      assert :waiting = CeremonyOrchestrator.check_readiness(ctx.tenant_id, ceremony.id)
    end

    test "returns :ready when all accepted and preparation attested", ctx do
      params = initiate_params(ctx)
      {:ok, {ceremony, _, _}} = CeremonyOrchestrator.initiate(ctx.tenant_id, ctx.ca.id, params)

      CeremonyOrchestrator.accept_share(ctx.tenant_id, ceremony.id, ctx.km1, "key1")
      CeremonyOrchestrator.accept_share(ctx.tenant_id, ceremony.id, ctx.km2, "key2")
      CeremonyOrchestrator.accept_share(ctx.tenant_id, ceremony.id, ctx.km3, "key3")
      CeremonyOrchestrator.attest(ctx.tenant_id, ceremony.id, ctx.auditor_id, "preparation")

      assert :ready = CeremonyOrchestrator.check_readiness(ctx.tenant_id, ceremony.id)
    end
  end

  describe "execute_keygen/3" do
    test "generates keypair, splits shares, completes ceremony", ctx do
      params = initiate_params(ctx)
      {:ok, {ceremony, _, _}} = CeremonyOrchestrator.initiate(ctx.tenant_id, ctx.ca.id, params)

      # Simulate custodian passwords
      passwords = [{ctx.km1, "password1"}, {ctx.km2, "password2"}, {ctx.km3, "password3"}]

      # Accept all shares
      CeremonyOrchestrator.accept_share(ctx.tenant_id, ceremony.id, ctx.km1, "key1")
      CeremonyOrchestrator.accept_share(ctx.tenant_id, ceremony.id, ctx.km2, "key2")
      CeremonyOrchestrator.accept_share(ctx.tenant_id, ceremony.id, ctx.km3, "key3")

      {:ok, result} = CeremonyOrchestrator.execute_keygen(ctx.tenant_id, ceremony.id, passwords)

      assert result.fingerprint != nil
      assert is_binary(result.fingerprint)

      # Verify ceremony is completed
      completed = Repo.get!(KeyCeremony, ceremony.id)
      assert completed.status == "completed"
      assert completed.domain_info["fingerprint"] != nil

      # Verify shares have encrypted data
      shares = Repo.all(from s in ThresholdShare, where: s.issuer_key_id == ^completed.issuer_key_id)
      Enum.each(shares, fn share ->
        assert share.encrypted_share != nil
        assert byte_size(share.encrypted_share) > 0
      end)
    end

    test "rejects keygen when ceremony is not preparing", ctx do
      params = initiate_params(ctx)
      {:ok, {ceremony, _, _}} = CeremonyOrchestrator.initiate(ctx.tenant_id, ctx.ca.id, params)

      ceremony |> Ecto.Changeset.change(%{status: "completed"}) |> Repo.update!()

      assert {:error, :invalid_status} = CeremonyOrchestrator.execute_keygen(ctx.tenant_id, ceremony.id, [])
    end

    test "root CA is automatically taken offline after keygen completes", ctx do
      # Verify CA starts online
      ca_before = Repo.get!(CaInstance, ctx.ca.id)
      refute ca_before.is_offline

      params = initiate_params(ctx, %{is_root: true})
      {:ok, {ceremony, _, _}} = CeremonyOrchestrator.initiate(ctx.tenant_id, ctx.ca.id, params)

      passwords = [{ctx.km1, "password1"}, {ctx.km2, "password2"}, {ctx.km3, "password3"}]
      CeremonyOrchestrator.accept_share(ctx.tenant_id, ceremony.id, ctx.km1, "key1")
      CeremonyOrchestrator.accept_share(ctx.tenant_id, ceremony.id, ctx.km2, "key2")
      CeremonyOrchestrator.accept_share(ctx.tenant_id, ceremony.id, ctx.km3, "key3")

      {:ok, _result} = CeremonyOrchestrator.execute_keygen(ctx.tenant_id, ceremony.id, passwords)

      # Root CA should now be offline
      ca_after = Repo.get!(CaInstance, ctx.ca.id)
      assert ca_after.is_offline
    end

    test "sub-CA keygen does NOT auto-offline the CA instance", ctx do
      # Create a sub-CA
      {:ok, sub_ca} = Repo.insert(CaInstance.changeset(%CaInstance{}, %{
        name: "sub-ca-orch-#{System.unique_integer([:positive])}",
        created_by: "test",
        parent_id: ctx.ca.id
      }))
      {:ok, sub_keystore} = Repo.insert(Keystore.changeset(%Keystore{}, %{
        ca_instance_id: sub_ca.id, type: "software"
      }))

      params = initiate_params(ctx, %{
        is_root: false,
        keystore_id: sub_keystore.id,
        domain_info: %{"is_root" => false, "subject_dn" => "/CN=Sub CA"}
      })
      {:ok, {ceremony, _, _}} = CeremonyOrchestrator.initiate(ctx.tenant_id, sub_ca.id, params)

      passwords = [{ctx.km1, "password1"}, {ctx.km2, "password2"}, {ctx.km3, "password3"}]
      CeremonyOrchestrator.accept_share(ctx.tenant_id, ceremony.id, ctx.km1, "key1")
      CeremonyOrchestrator.accept_share(ctx.tenant_id, ceremony.id, ctx.km2, "key2")
      CeremonyOrchestrator.accept_share(ctx.tenant_id, ceremony.id, ctx.km3, "key3")

      {:ok, _result} = CeremonyOrchestrator.execute_keygen(ctx.tenant_id, ceremony.id, passwords)

      # Sub-CA should remain online
      sub_ca_after = Repo.get!(CaInstance, sub_ca.id)
      refute sub_ca_after.is_offline
    end
  end

  describe "fail_ceremony/3" do
    test "marks ceremony as failed with reason", ctx do
      params = initiate_params(ctx)
      {:ok, {ceremony, _, _}} = CeremonyOrchestrator.initiate(ctx.tenant_id, ctx.ca.id, params)

      {:ok, failed} = CeremonyOrchestrator.fail_ceremony(ctx.tenant_id, ceremony.id, "window_expired")

      assert failed.status == "failed"
      assert failed.domain_info["failure_reason"] == "window_expired"
    end
  end

  describe "list_attestations/2" do
    test "returns attestations in order", ctx do
      params = initiate_params(ctx)
      {:ok, {ceremony, _, _}} = CeremonyOrchestrator.initiate(ctx.tenant_id, ctx.ca.id, params)

      CeremonyOrchestrator.attest(ctx.tenant_id, ceremony.id, ctx.auditor_id, "preparation")

      attestations = CeremonyOrchestrator.list_attestations(ctx.tenant_id, ceremony.id)
      assert length(attestations) == 1
      assert hd(attestations).phase == "preparation"
    end
  end
end
