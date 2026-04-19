defmodule PkiRaEngine.DcvChallengeMnesiaTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.TestHelper
  alias PkiRaEngine.DcvChallenge

  setup do
    dir = TestHelper.setup_mnesia()
    on_exit(fn -> TestHelper.teardown_mnesia(dir) end)
    :ok
  end

  test "create_challenge creates a pending challenge" do
    {:ok, challenge} = DcvChallenge.create_challenge("csr-1", "example.com")
    assert challenge.csr_request_id == "csr-1"
    assert challenge.domain == "example.com"
    assert challenge.status == "pending"
    assert challenge.challenge_type == "dns"
    assert is_binary(challenge.challenge_token)
  end

  test "verify_challenge with correct token succeeds" do
    {:ok, challenge} = DcvChallenge.create_challenge("csr-1", "example.com")
    {:ok, verified} = DcvChallenge.verify_challenge(challenge.id, challenge.challenge_token)
    assert verified.status == "verified"
    assert verified.verified_at != nil
  end

  test "verify_challenge with wrong token fails" do
    {:ok, challenge} = DcvChallenge.create_challenge("csr-1", "example.com")
    assert {:error, :invalid_token} = DcvChallenge.verify_challenge(challenge.id, "wrong-token")
  end

  test "verify_challenge on already verified challenge fails" do
    {:ok, challenge} = DcvChallenge.create_challenge("csr-1", "example.com")
    {:ok, _} = DcvChallenge.verify_challenge(challenge.id, challenge.challenge_token)
    assert {:error, :already_verified} = DcvChallenge.verify_challenge(challenge.id, challenge.challenge_token)
  end

  test "verify_challenge on non-existent id fails" do
    assert {:error, :not_found} = DcvChallenge.verify_challenge("nonexistent", "token")
  end

  test "check_dcv_passed returns ok when all challenges verified" do
    {:ok, c1} = DcvChallenge.create_challenge("csr-1", "example.com")
    {:ok, c2} = DcvChallenge.create_challenge("csr-1", "www.example.com")
    {:ok, _} = DcvChallenge.verify_challenge(c1.id, c1.challenge_token)
    {:ok, _} = DcvChallenge.verify_challenge(c2.id, c2.challenge_token)

    assert :ok = DcvChallenge.check_dcv_passed("csr-1")
  end

  test "check_dcv_passed returns error when not all verified" do
    {:ok, c1} = DcvChallenge.create_challenge("csr-2", "example.com")
    {:ok, _c2} = DcvChallenge.create_challenge("csr-2", "www.example.com")
    {:ok, _} = DcvChallenge.verify_challenge(c1.id, c1.challenge_token)

    assert {:error, :dcv_not_complete} = DcvChallenge.check_dcv_passed("csr-2")
  end

  test "check_dcv_passed returns error when no challenges exist" do
    assert {:error, :no_dcv_challenge} = DcvChallenge.check_dcv_passed("csr-no-exist")
  end

  test "get_challenge returns the challenge" do
    {:ok, challenge} = DcvChallenge.create_challenge("csr-1", "example.com")
    {:ok, fetched} = DcvChallenge.get_challenge(challenge.id)
    assert fetched.id == challenge.id
  end

  test "get_for_csr returns all challenges for a CSR" do
    {:ok, _} = DcvChallenge.create_challenge("csr-3", "example.com")
    {:ok, _} = DcvChallenge.create_challenge("csr-3", "www.example.com")
    {:ok, _} = DcvChallenge.create_challenge("csr-other", "other.com")

    {:ok, challenges} = DcvChallenge.get_for_csr("csr-3")
    assert length(challenges) == 2
  end
end
