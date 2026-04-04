defmodule PkiRaEngine.DcvChallengeTest do
  @moduledoc """
  Module-level tests for DcvChallenge: create, verify, expiry, get_for_csr, check_dcv_passed.
  """
  use PkiRaEngine.DataCase, async: false

  alias PkiRaEngine.DcvChallenge
  alias PkiRaEngine.CsrValidation
  alias PkiRaEngine.CertProfileConfig

  defp create_profile! do
    {:ok, profile} = CertProfileConfig.create_profile(nil, %{name: "dcv_profile_#{System.unique_integer([:positive])}"})
    profile
  end

  defp create_csr!(profile) do
    csr_pem = "-----BEGIN CERTIFICATE REQUEST-----\nMIIBdcv#{System.unique_integer([:positive])}\n-----END CERTIFICATE REQUEST-----"
    {:ok, csr} = CsrValidation.submit_csr(nil, csr_pem, profile.id)
    csr
  end

  # -- create/6 --

  describe "create/6" do
    test "creates an HTTP-01 challenge with token and expiry" do
      profile = create_profile!()
      csr = create_csr!(profile)

      assert {:ok, challenge} = DcvChallenge.create(nil, csr.id, "example.com", "http-01", nil)

      assert challenge.domain == "example.com"
      assert challenge.method == "http-01"
      assert challenge.status == "pending"
      assert challenge.token != nil
      assert challenge.token_value != nil
      assert challenge.expires_at != nil
      assert challenge.attempts == 0
      assert challenge.csr_id == csr.id
    end

    test "creates a DNS-01 challenge" do
      profile = create_profile!()
      csr = create_csr!(profile)

      assert {:ok, challenge} = DcvChallenge.create(nil, csr.id, "example.com", "dns-01", nil)

      assert challenge.method == "dns-01"
      assert challenge.status == "pending"
    end

    test "sets initiated_by when provided" do
      profile = create_profile!()
      csr = create_csr!(profile)
      user_id = Uniq.UUID.uuid7()

      assert {:ok, challenge} = DcvChallenge.create(nil, csr.id, "example.com", "http-01", user_id)

      assert challenge.initiated_by == user_id
    end

    test "respects custom timeout_hours" do
      profile = create_profile!()
      csr = create_csr!(profile)

      assert {:ok, challenge} = DcvChallenge.create(nil, csr.id, "example.com", "http-01", nil, 48)

      # Expiry should be ~48 hours from now
      diff = DateTime.diff(challenge.expires_at, DateTime.utc_now(), :hour)
      assert diff >= 47 and diff <= 48
    end

    test "fails with invalid method" do
      profile = create_profile!()
      csr = create_csr!(profile)

      assert {:error, changeset} = DcvChallenge.create(nil, csr.id, "example.com", "email-01", nil)
      assert errors_on(changeset)[:method]
    end

    test "fails with non-existent CSR" do
      assert {:error, _} = DcvChallenge.create(nil, Uniq.UUID.uuid7(), "example.com", "http-01", nil)
    end
  end

  # -- get_for_csr/2 --

  describe "get_for_csr/2" do
    test "returns all challenges for a CSR" do
      profile = create_profile!()
      csr = create_csr!(profile)

      {:ok, _} = DcvChallenge.create(nil, csr.id, "a.example.com", "http-01", nil)
      {:ok, _} = DcvChallenge.create(nil, csr.id, "b.example.com", "dns-01", nil)

      challenges = DcvChallenge.get_for_csr(nil, csr.id)
      assert length(challenges) == 2
    end

    test "returns empty list for CSR with no challenges" do
      profile = create_profile!()
      csr = create_csr!(profile)

      assert DcvChallenge.get_for_csr(nil, csr.id) == []
    end

    test "does not return challenges from other CSRs" do
      profile = create_profile!()
      csr1 = create_csr!(profile)
      csr2 = create_csr!(profile)

      {:ok, _} = DcvChallenge.create(nil, csr1.id, "example.com", "http-01", nil)
      {:ok, _} = DcvChallenge.create(nil, csr2.id, "other.com", "http-01", nil)

      challenges = DcvChallenge.get_for_csr(nil, csr1.id)
      assert length(challenges) == 1
      assert hd(challenges).domain == "example.com"
    end
  end

  # -- check_dcv_passed/2 --

  describe "check_dcv_passed/2" do
    test "returns error when no challenges exist" do
      profile = create_profile!()
      csr = create_csr!(profile)

      assert {:error, :dcv_not_passed} = DcvChallenge.check_dcv_passed(nil, csr.id)
    end

    test "returns error when all challenges are pending" do
      profile = create_profile!()
      csr = create_csr!(profile)

      {:ok, _} = DcvChallenge.create(nil, csr.id, "example.com", "http-01", nil)

      assert {:error, :dcv_not_passed} = DcvChallenge.check_dcv_passed(nil, csr.id)
    end

    test "returns ok when at least one challenge has passed" do
      profile = create_profile!()
      csr = create_csr!(profile)

      {:ok, challenge} = DcvChallenge.create(nil, csr.id, "example.com", "http-01", nil)

      # Manually set status to passed
      repo = PkiRaEngine.Repo
      challenge
      |> PkiRaEngine.Schema.DcvChallenge.changeset(%{status: "passed", verified_at: DateTime.utc_now()})
      |> repo.update!()

      assert :ok = DcvChallenge.check_dcv_passed(nil, csr.id)
    end
  end

  # -- expire_overdue/1 --

  describe "expire_overdue/1" do
    test "expires pending challenges past their expiry" do
      profile = create_profile!()
      csr = create_csr!(profile)

      # Create a challenge that expires 1 hour ago
      {:ok, challenge} = DcvChallenge.create(nil, csr.id, "example.com", "http-01", nil, 0)

      # Manually set expires_at to the past
      repo = PkiRaEngine.Repo
      past = DateTime.add(DateTime.utc_now(), -3600, :second) |> DateTime.truncate(:second)

      challenge
      |> PkiRaEngine.Schema.DcvChallenge.changeset(%{expires_at: past})
      |> repo.update!()

      {count, _} = DcvChallenge.expire_overdue(nil)
      assert count >= 1

      # Verify the challenge is now expired
      [updated] = DcvChallenge.get_for_csr(nil, csr.id)
      assert updated.status == "expired"
    end

    test "does not expire challenges that haven't reached expiry" do
      profile = create_profile!()
      csr = create_csr!(profile)

      {:ok, _} = DcvChallenge.create(nil, csr.id, "example.com", "http-01", nil, 24)

      {count, _} = DcvChallenge.expire_overdue(nil)
      assert count == 0
    end
  end

  # -- verify/2 --

  describe "verify/2" do
    test "cannot verify a non-pending challenge" do
      profile = create_profile!()
      csr = create_csr!(profile)

      {:ok, challenge} = DcvChallenge.create(nil, csr.id, "example.com", "http-01", nil)

      # Manually set status to expired
      repo = PkiRaEngine.Repo
      challenge
      |> PkiRaEngine.Schema.DcvChallenge.changeset(%{status: "expired"})
      |> repo.update!()

      assert {:error, {:not_verifiable, "expired"}} = DcvChallenge.verify(nil, challenge.id)
    end

    test "returns not_found for non-existent challenge" do
      assert {:error, :not_found} = DcvChallenge.verify(nil, Uniq.UUID.uuid7())
    end
  end

  # -- list_pending/1 --

  describe "list_pending/1" do
    test "returns only pending non-expired challenges" do
      profile = create_profile!()
      csr = create_csr!(profile)

      {:ok, _} = DcvChallenge.create(nil, csr.id, "pending.com", "http-01", nil, 24)
      {:ok, passed_ch} = DcvChallenge.create(nil, csr.id, "passed.com", "dns-01", nil, 24)

      # Mark one as passed
      repo = PkiRaEngine.Repo
      passed_ch
      |> PkiRaEngine.Schema.DcvChallenge.changeset(%{status: "passed"})
      |> repo.update!()

      pending = DcvChallenge.list_pending(nil)
      assert length(pending) == 1
      assert hd(pending).domain == "pending.com"
    end
  end
end
