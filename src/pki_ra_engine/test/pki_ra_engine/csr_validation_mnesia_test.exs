defmodule PkiRaEngine.CsrValidationMnesiaTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.{TestHelper, Repo}
  alias PkiRaEngine.{CsrValidation, CertProfileConfig}

  setup do
    dir = TestHelper.setup_mnesia()
    on_exit(fn -> TestHelper.teardown_mnesia(dir) end)

    # Create a cert profile for testing
    {:ok, profile} =
      CertProfileConfig.create_profile(%{
        name: "Test Profile",
        issuer_key_id: "fake-key-id",
        validity_days: 365,
        approval_mode: "manual"
      })

    %{profile: profile}
  end

  test "submit_csr creates a pending CSR", %{profile: profile} do
    {:ok, csr} = CsrValidation.submit_csr("fake-csr-pem", profile.id)
    assert csr.status == "pending"
    assert csr.cert_profile_id == profile.id
  end

  test "get_csr returns the CSR by id", %{profile: profile} do
    {:ok, csr} = CsrValidation.submit_csr("fake-csr-pem", profile.id)
    assert {:ok, fetched} = CsrValidation.get_csr(csr.id)
    assert fetched.id == csr.id
  end

  test "get_csr returns error for non-existent id" do
    assert {:error, :not_found} = CsrValidation.get_csr("nonexistent")
  end

  test "reject_csr transitions verified -> rejected", %{profile: profile} do
    {:ok, csr} = CsrValidation.submit_csr("fake-csr-pem", profile.id)
    # Manually set to verified for test
    {:ok, verified} = Repo.update(csr, %{status: "verified"})

    {:ok, rejected} = CsrValidation.reject_csr(verified.id, "officer-1", "bad CSR")
    assert rejected.status == "rejected"
    assert rejected.rejection_reason == "bad CSR"
  end

  test "approve_csr rejects invalid transition from pending", %{profile: profile} do
    {:ok, csr} = CsrValidation.submit_csr("fake-csr-pem", profile.id)

    assert {:error, {:invalid_transition, "pending", "approved"}} =
             CsrValidation.approve_csr(csr.id, "officer-1")
  end

  test "list_csrs returns all CSRs", %{profile: profile} do
    {:ok, _} = CsrValidation.submit_csr("csr-1", profile.id)
    {:ok, _} = CsrValidation.submit_csr("csr-2", profile.id)

    {:ok, csrs} = CsrValidation.list_csrs()
    assert length(csrs) == 2
  end

  test "list_csrs filters by status", %{profile: profile} do
    {:ok, csr1} = CsrValidation.submit_csr("csr-1", profile.id)
    {:ok, _csr2} = CsrValidation.submit_csr("csr-2", profile.id)
    {:ok, _} = Repo.update(csr1, %{status: "verified"})

    {:ok, pending} = CsrValidation.list_csrs(status: "pending")
    assert length(pending) == 1
  end

  test "validate_csr moves pending to verified when CSR is valid", %{profile: profile} do
    {:ok, csr} = CsrValidation.submit_csr("fake-csr-pem-data", profile.id)
    {:ok, validated} = CsrValidation.validate_csr(csr.id)
    assert validated.status == "verified"
  end

  test "approve then mark_issued works on verified CSR", %{profile: profile} do
    {:ok, csr} = CsrValidation.submit_csr("fake-csr-pem", profile.id)
    {:ok, verified} = Repo.update(csr, %{status: "verified"})

    {:ok, approved} = CsrValidation.approve_csr(verified.id, "officer-1")
    assert approved.status == "approved"

    # Transition through "signing" state (D14 double-sign protection)
    {:ok, signing} = Repo.update(approved, %{status: "signing"})
    assert signing.status == "signing"

    {:ok, issued} = CsrValidation.mark_issued(signing.id, "SERIAL-001")
    assert issued.status == "issued"
    assert issued.issued_cert_serial == "SERIAL-001"
  end
end
