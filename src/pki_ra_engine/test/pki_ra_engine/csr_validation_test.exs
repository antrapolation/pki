defmodule PkiRaEngine.CsrValidationTest do
  use PkiRaEngine.DataCase, async: true

  alias PkiRaEngine.CsrValidation
  alias PkiRaEngine.CertProfileConfig
  alias PkiRaEngine.UserManagement

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

  defp submit_csr!(profile, csr_pem \\ "-----BEGIN CERTIFICATE REQUEST-----\nMIIB...fake\n-----END CERTIFICATE REQUEST-----") do
    {:ok, csr} = CsrValidation.submit_csr(csr_pem, profile.id)
    csr
  end

  describe "submit_csr/2" do
    test "stores CSR with pending status and submitted_at" do
      profile = create_profile!()
      csr_pem = "-----BEGIN CERTIFICATE REQUEST-----\nMIIBtest\n-----END CERTIFICATE REQUEST-----"

      assert {:ok, csr} = CsrValidation.submit_csr(csr_pem, profile.id)
      assert csr.status == "pending"
      assert csr.csr_pem == csr_pem
      assert csr.cert_profile_id == profile.id
      assert csr.submitted_at != nil
    end

    test "fails with non-existent profile" do
      assert {:error, _reason} = CsrValidation.submit_csr("some csr", 999_999)
    end
  end

  describe "validate_csr/1" do
    test "sets status to verified for valid CSR" do
      profile = create_profile!()
      csr = submit_csr!(profile)

      assert {:ok, validated} = CsrValidation.validate_csr(csr.id)
      assert validated.status == "verified"
    end

    test "sets status to rejected for empty CSR" do
      profile = create_profile!()
      {:ok, csr} =
        CsrValidation.submit_csr("", profile.id)

      # Empty CSR should fail — but submit stores it, validate rejects it
      # Actually submit should still work (stores pending), validate catches issues
      assert {:ok, validated} = CsrValidation.validate_csr(csr.id)
      assert validated.status == "rejected"
    end

    test "rejects CSR with non-existent profile" do
      profile = create_profile!()
      csr = submit_csr!(profile)
      # Remove FK constraint temporarily and delete the profile to simulate missing profile
      Repo.query!("ALTER TABLE csr_requests DROP CONSTRAINT csr_requests_cert_profile_id_fkey")
      Repo.query!("DELETE FROM cert_profiles WHERE id = $1", [profile.id])

      assert {:ok, validated} = CsrValidation.validate_csr(csr.id)
      assert validated.status == "rejected"
    end

    test "only works on pending CSRs" do
      profile = create_profile!()
      csr = submit_csr!(profile)
      {:ok, verified} = CsrValidation.validate_csr(csr.id)
      assert verified.status == "verified"

      # Trying to validate again should fail
      assert {:error, {:invalid_transition, "verified", "verified"}} =
               CsrValidation.validate_csr(verified.id)
    end
  end

  describe "approve_csr/2" do
    test "approves a verified CSR" do
      profile = create_profile!()
      officer = create_officer!()
      csr = submit_csr!(profile)
      {:ok, verified} = CsrValidation.validate_csr(csr.id)

      assert {:ok, approved} = CsrValidation.approve_csr(verified.id, officer.id)
      assert approved.status == "approved"
      assert approved.reviewed_by == officer.id
      assert approved.reviewed_at != nil
    end

    test "cannot approve a pending CSR" do
      profile = create_profile!()
      officer = create_officer!()
      csr = submit_csr!(profile)

      assert {:error, {:invalid_transition, "pending", "approved"}} =
               CsrValidation.approve_csr(csr.id, officer.id)
    end

    test "cannot approve an already approved CSR" do
      profile = create_profile!()
      officer = create_officer!()
      csr = submit_csr!(profile)
      {:ok, verified} = CsrValidation.validate_csr(csr.id)
      {:ok, approved} = CsrValidation.approve_csr(verified.id, officer.id)

      assert {:error, {:invalid_transition, "approved", "approved"}} =
               CsrValidation.approve_csr(approved.id, officer.id)
    end
  end

  describe "reject_csr/3" do
    test "rejects a verified CSR with reason" do
      profile = create_profile!()
      officer = create_officer!()
      csr = submit_csr!(profile)
      {:ok, verified} = CsrValidation.validate_csr(csr.id)

      assert {:ok, rejected} = CsrValidation.reject_csr(verified.id, officer.id, "Policy violation")
      assert rejected.status == "rejected"
      assert rejected.reviewed_by == officer.id
      assert rejected.rejection_reason == "Policy violation"
      assert rejected.reviewed_at != nil
    end

    test "cannot reject a pending CSR" do
      profile = create_profile!()
      officer = create_officer!()
      csr = submit_csr!(profile)

      assert {:error, {:invalid_transition, "pending", "rejected"}} =
               CsrValidation.reject_csr(csr.id, officer.id, "bad")
    end

    test "cannot reject an already approved CSR" do
      profile = create_profile!()
      officer = create_officer!()
      csr = submit_csr!(profile)
      {:ok, verified} = CsrValidation.validate_csr(csr.id)
      {:ok, approved} = CsrValidation.approve_csr(verified.id, officer.id)

      assert {:error, {:invalid_transition, "approved", "rejected"}} =
               CsrValidation.reject_csr(approved.id, officer.id, "too late")
    end
  end

  describe "get_csr/1" do
    test "returns CSR by id" do
      profile = create_profile!()
      csr = submit_csr!(profile)

      assert {:ok, found} = CsrValidation.get_csr(csr.id)
      assert found.id == csr.id
    end

    test "returns error for non-existent id" do
      assert {:error, :not_found} = CsrValidation.get_csr(999_999)
    end
  end

  describe "list_csrs/1" do
    test "lists all CSRs with no filters" do
      profile = create_profile!()
      submit_csr!(profile)
      submit_csr!(profile)

      csrs = CsrValidation.list_csrs([])
      assert length(csrs) == 2
    end

    test "filters by status" do
      profile = create_profile!()
      csr1 = submit_csr!(profile)
      _csr2 = submit_csr!(profile)
      CsrValidation.validate_csr(csr1.id)

      csrs = CsrValidation.list_csrs(status: "verified")
      assert length(csrs) == 1
      assert hd(csrs).status == "verified"
    end

    test "filters by cert_profile_id" do
      profile1 = create_profile!()
      profile2 = create_profile!()
      submit_csr!(profile1)
      submit_csr!(profile2)

      csrs = CsrValidation.list_csrs(cert_profile_id: profile1.id)
      assert length(csrs) == 1
      assert hd(csrs).cert_profile_id == profile1.id
    end
  end

  describe "mark_issued/2" do
    test "marks an approved CSR as issued with cert serial" do
      profile = create_profile!()
      officer = create_officer!()
      csr = submit_csr!(profile)
      {:ok, verified} = CsrValidation.validate_csr(csr.id)
      {:ok, approved} = CsrValidation.approve_csr(verified.id, officer.id)

      assert {:ok, issued} = CsrValidation.mark_issued(approved.id, "SERIAL123ABC")
      assert issued.status == "issued"
      assert issued.issued_cert_serial == "SERIAL123ABC"
    end

    test "cannot mark a pending CSR as issued" do
      profile = create_profile!()
      csr = submit_csr!(profile)

      assert {:error, {:invalid_transition, "pending", "issued"}} =
               CsrValidation.mark_issued(csr.id, "SERIAL")
    end

    test "cannot mark a verified CSR as issued" do
      profile = create_profile!()
      csr = submit_csr!(profile)
      {:ok, verified} = CsrValidation.validate_csr(csr.id)

      assert {:error, {:invalid_transition, "verified", "issued"}} =
               CsrValidation.mark_issued(verified.id, "SERIAL")
    end
  end
end
