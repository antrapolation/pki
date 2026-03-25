defmodule PkiRaEngine.CsrTransitionsTest do
  @moduledoc """
  Exhaustive state machine transition tests for CSR status lifecycle.

  Covers UC-RA-21 (CSR validation) and UC-RA-30 (CSR status transitions).

  Valid transitions:
    pending  -> verified   (auto-validation pass)
    pending  -> rejected   (auto-validation fail)
    verified -> approved   (officer approval)
    verified -> rejected   (officer rejection)
    approved -> issued     (CA signs certificate)

  All other transitions must be rejected.
  """
  use PkiRaEngine.DataCase, async: false

  alias PkiRaEngine.CsrValidation
  alias PkiRaEngine.CertProfileConfig
  alias PkiRaEngine.UserManagement

  @statuses ["pending", "verified", "approved", "rejected", "issued"]

  defp create_profile! do
    {:ok, profile} = CertProfileConfig.create_profile(%{name: "test_tls_#{System.unique_integer([:positive])}"})
    profile
  end

  defp create_officer! do
    {:ok, user} =
      UserManagement.create_user(%{
        did: "did:example:officer_#{System.unique_integer([:positive])}",
        display_name: "Officer",
        role: "ra_officer"
      })

    user
  end

  defp submit_csr!(profile) do
    csr_pem = "-----BEGIN CERTIFICATE REQUEST-----\nMIIB...fake-#{System.unique_integer([:positive])}\n-----END CERTIFICATE REQUEST-----"
    {:ok, csr} = CsrValidation.submit_csr(csr_pem, profile.id)
    csr
  end

  defp create_csr_in_status!(profile, officer, status) do
    csr = submit_csr!(profile)

    case status do
      "pending" ->
        csr

      "verified" ->
        {:ok, verified} = CsrValidation.validate_csr(csr.id)
        verified

      "approved" ->
        {:ok, verified} = CsrValidation.validate_csr(csr.id)
        {:ok, approved} = CsrValidation.approve_csr(verified.id, officer.id)
        approved

      "rejected" ->
        {:ok, verified} = CsrValidation.validate_csr(csr.id)
        {:ok, rejected} = CsrValidation.reject_csr(verified.id, officer.id, "test rejection")
        rejected

      "issued" ->
        {:ok, verified} = CsrValidation.validate_csr(csr.id)
        {:ok, approved} = CsrValidation.approve_csr(verified.id, officer.id)
        {:ok, issued} = CsrValidation.mark_issued(approved.id, "SERIAL-#{System.unique_integer([:positive])}")
        issued
    end
  end

  setup do
    profile = create_profile!()
    officer = create_officer!()
    %{profile: profile, officer: officer}
  end

  # ── Invalid transitions: pending ────────────────────────────────────────

  describe "invalid transitions from pending" do
    test "pending -> approved is rejected (must go through verified)", %{profile: profile, officer: officer} do
      csr = create_csr_in_status!(profile, officer, "pending")

      assert {:error, {:invalid_transition, "pending", "approved"}} =
               CsrValidation.approve_csr(csr.id, officer.id)
    end

    test "pending -> issued is rejected", %{profile: profile, officer: officer} do
      csr = create_csr_in_status!(profile, officer, "pending")

      assert {:error, {:invalid_transition, "pending", "issued"}} =
               CsrValidation.mark_issued(csr.id, "SERIAL-123")
    end

    test "pending -> rejected via officer reject is rejected (only auto-validation can reject pending)", %{profile: profile, officer: officer} do
      csr = create_csr_in_status!(profile, officer, "pending")

      assert {:error, {:invalid_transition, "pending", "rejected"}} =
               CsrValidation.reject_csr(csr.id, officer.id, "bad")
    end
  end

  # ── Invalid transitions: verified ───────────────────────────────────────

  describe "invalid transitions from verified" do
    test "verified -> issued is rejected (must go through approved)", %{profile: profile, officer: officer} do
      csr = create_csr_in_status!(profile, officer, "verified")

      assert {:error, {:invalid_transition, "verified", "issued"}} =
               CsrValidation.mark_issued(csr.id, "SERIAL-456")
    end

    test "verified -> pending is rejected (cannot re-validate)", %{profile: profile, officer: officer} do
      csr = create_csr_in_status!(profile, officer, "verified")

      # There is no API to move back to pending; validate_csr checks auto_transition
      # verified -> verified is also invalid
      assert {:error, {:invalid_transition, "verified", "verified"}} =
               CsrValidation.validate_csr(csr.id)
    end
  end

  # ── Invalid transitions: rejected ───────────────────────────────────────

  describe "invalid transitions from rejected" do
    test "rejected -> approved is rejected", %{profile: profile, officer: officer} do
      csr = create_csr_in_status!(profile, officer, "rejected")

      assert {:error, {:invalid_transition, "rejected", "approved"}} =
               CsrValidation.approve_csr(csr.id, officer.id)
    end

    test "rejected -> verified is rejected", %{profile: profile, officer: officer} do
      csr = create_csr_in_status!(profile, officer, "rejected")

      # validate_csr checks auto_transition from current status
      assert {:error, {:invalid_transition, "rejected", "verified"}} =
               CsrValidation.validate_csr(csr.id)
    end

    test "rejected -> issued is rejected", %{profile: profile, officer: officer} do
      csr = create_csr_in_status!(profile, officer, "rejected")

      assert {:error, {:invalid_transition, "rejected", "issued"}} =
               CsrValidation.mark_issued(csr.id, "SERIAL-789")
    end

    test "rejected -> rejected via officer reject is rejected", %{profile: profile, officer: officer} do
      csr = create_csr_in_status!(profile, officer, "rejected")

      assert {:error, {:invalid_transition, "rejected", "rejected"}} =
               CsrValidation.reject_csr(csr.id, officer.id, "double reject")
    end
  end

  # ── Invalid transitions: issued ─────────────────────────────────────────

  describe "invalid transitions from issued" do
    test "issued -> approved is rejected", %{profile: profile, officer: officer} do
      csr = create_csr_in_status!(profile, officer, "issued")

      assert {:error, {:invalid_transition, "issued", "approved"}} =
               CsrValidation.approve_csr(csr.id, officer.id)
    end

    test "issued -> rejected is rejected", %{profile: profile, officer: officer} do
      csr = create_csr_in_status!(profile, officer, "issued")

      assert {:error, {:invalid_transition, "issued", "rejected"}} =
               CsrValidation.reject_csr(csr.id, officer.id, "too late")
    end

    test "issued -> pending is rejected (no mechanism to reset)", %{profile: profile, officer: officer} do
      csr = create_csr_in_status!(profile, officer, "issued")

      # validate_csr would try issued -> verified (auto transition check)
      assert {:error, {:invalid_transition, "issued", "verified"}} =
               CsrValidation.validate_csr(csr.id)
    end

    test "issued -> issued is rejected (cannot re-issue)", %{profile: profile, officer: officer} do
      csr = create_csr_in_status!(profile, officer, "issued")

      assert {:error, {:invalid_transition, "issued", "issued"}} =
               CsrValidation.mark_issued(csr.id, "SERIAL-AGAIN")
    end
  end

  # ── Invalid transitions: approved ───────────────────────────────────────

  describe "invalid transitions from approved" do
    test "approved -> verified is rejected", %{profile: profile, officer: officer} do
      csr = create_csr_in_status!(profile, officer, "approved")

      # validate_csr checks auto_transition from approved -> verified
      assert {:error, {:invalid_transition, "approved", "verified"}} =
               CsrValidation.validate_csr(csr.id)
    end

    test "approved -> pending is rejected (no mechanism to reset)", %{profile: profile, officer: officer} do
      csr = create_csr_in_status!(profile, officer, "approved")

      # No direct API for this; validate_csr would try approved -> verified
      assert {:error, {:invalid_transition, "approved", "verified"}} =
               CsrValidation.validate_csr(csr.id)
    end

    test "approved -> approved is rejected (cannot double-approve)", %{profile: profile, officer: officer} do
      csr = create_csr_in_status!(profile, officer, "approved")

      assert {:error, {:invalid_transition, "approved", "approved"}} =
               CsrValidation.approve_csr(csr.id, officer.id)
    end

    test "approved -> rejected is rejected (cannot reject after approval)", %{profile: profile, officer: officer} do
      csr = create_csr_in_status!(profile, officer, "approved")

      assert {:error, {:invalid_transition, "approved", "rejected"}} =
               CsrValidation.reject_csr(csr.id, officer.id, "changed mind")
    end
  end

  # ── Valid transition paths (happy path confirmation) ────────────────────

  describe "valid transition paths" do
    test "full happy path: pending -> verified -> approved -> issued", %{profile: profile, officer: officer} do
      csr = submit_csr!(profile)
      assert csr.status == "pending"

      {:ok, verified} = CsrValidation.validate_csr(csr.id)
      assert verified.status == "verified"

      {:ok, approved} = CsrValidation.approve_csr(verified.id, officer.id)
      assert approved.status == "approved"

      {:ok, issued} = CsrValidation.mark_issued(approved.id, "SERIAL-HAPPY")
      assert issued.status == "issued"
      assert issued.issued_cert_serial == "SERIAL-HAPPY"
    end

    test "rejection path: pending -> verified -> rejected", %{profile: profile, officer: officer} do
      csr = submit_csr!(profile)

      {:ok, verified} = CsrValidation.validate_csr(csr.id)
      assert verified.status == "verified"

      {:ok, rejected} = CsrValidation.reject_csr(verified.id, officer.id, "Policy violation")
      assert rejected.status == "rejected"
      assert rejected.rejection_reason == "Policy violation"
    end

    test "auto-rejection path: pending -> rejected (via validate_csr with empty CSR)", %{profile: profile} do
      # Submit an empty CSR that will fail auto-validation
      {:ok, csr} = CsrValidation.submit_csr("", profile.id)
      assert csr.status == "pending"

      {:ok, rejected} = CsrValidation.validate_csr(csr.id)
      assert rejected.status == "rejected"
    end
  end

  # ── Terminal state verification ─────────────────────────────────────────

  describe "terminal states" do
    test "rejected is terminal - no transitions out", %{profile: profile, officer: officer} do
      csr = create_csr_in_status!(profile, officer, "rejected")

      assert {:error, {:invalid_transition, "rejected", "approved"}} =
               CsrValidation.approve_csr(csr.id, officer.id)

      assert {:error, {:invalid_transition, "rejected", "rejected"}} =
               CsrValidation.reject_csr(csr.id, officer.id, "again")

      assert {:error, {:invalid_transition, "rejected", "issued"}} =
               CsrValidation.mark_issued(csr.id, "SERIAL")

      assert {:error, {:invalid_transition, "rejected", "verified"}} =
               CsrValidation.validate_csr(csr.id)
    end

    test "issued is terminal - no transitions out", %{profile: profile, officer: officer} do
      csr = create_csr_in_status!(profile, officer, "issued")

      assert {:error, {:invalid_transition, "issued", "approved"}} =
               CsrValidation.approve_csr(csr.id, officer.id)

      assert {:error, {:invalid_transition, "issued", "rejected"}} =
               CsrValidation.reject_csr(csr.id, officer.id, "nope")

      assert {:error, {:invalid_transition, "issued", "issued"}} =
               CsrValidation.mark_issued(csr.id, "SERIAL")

      assert {:error, {:invalid_transition, "issued", "verified"}} =
               CsrValidation.validate_csr(csr.id)
    end
  end
end
