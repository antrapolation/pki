defmodule PkiCaEngine.KeyModeTest do
  @moduledoc """
  End-to-end tests for the three key_mode options introduced in E1.7:
    - "threshold"        — Shamir split, n >= 2, k >= 2
    - "password"         — n=1, k=1 single encrypted blob
    - "single_custodian" — same as "password" mechanically (n=1, k=1)
  """
  use ExUnit.Case, async: false

  alias PkiMnesia.{TestHelper, Repo}
  alias PkiMnesia.Structs.ThresholdShare
  alias PkiCaEngine.CeremonyOrchestrator

  setup do
    dir = TestHelper.setup_mnesia()

    on_exit(fn ->
      TestHelper.teardown_mnesia(dir)
    end)

    :ok
  end

  # ---------------------------------------------------------------------------
  # threshold mode (default Shamir flow)
  # ---------------------------------------------------------------------------

  describe "key_mode: threshold" do
    test "initiate persists key_mode = threshold on IssuerKey" do
      {:ok, {_ceremony, key, _shares, _participants, _transcript}} =
        create_ceremony("threshold", 2, 3, ["Alice", "Bob", "Charlie"])

      assert key.key_mode == "threshold"
    end

    test "end-to-end: shares have n=3, k=2 after keygen" do
      {:ok, {ceremony, _key, _shares, _participants, _transcript}} =
        create_ceremony("threshold", 2, 3, ["Alice", "Bob", "Charlie"])

      {:ok, _} = CeremonyOrchestrator.accept_share(ceremony.id, "Alice", "alice-pw")
      {:ok, _} = CeremonyOrchestrator.accept_share(ceremony.id, "Bob", "bob-pw")
      {:ok, _} = CeremonyOrchestrator.accept_share(ceremony.id, "Charlie", "charlie-pw")

      passwords = [{"Alice", "alice-pw"}, {"Bob", "bob-pw"}, {"Charlie", "charlie-pw"}]
      assert {:ok, _result} = CeremonyOrchestrator.execute_keygen(ceremony.id, passwords)

      {:ok, shares} = Repo.get_all_by_index(ThresholdShare, :issuer_key_id, ceremony.issuer_key_id)
      active_shares = Enum.filter(shares, &(&1.status == "active"))

      assert length(active_shares) >= 2,
             "threshold mode should produce at least 2 active shares, got #{length(active_shares)}"

      for share <- active_shares do
        assert share.total_shares >= 2,
               "total_shares should be >= 2 in threshold mode, got #{share.total_shares}"
        assert share.min_shares >= 2,
               "min_shares should be >= 2 in threshold mode, got #{share.min_shares}"
        assert share.encrypted_share != nil
        assert share.password_hash == nil
      end
    end
  end

  # ---------------------------------------------------------------------------
  # password mode (single-custodian AES-GCM envelope)
  # ---------------------------------------------------------------------------

  describe "key_mode: password" do
    test "initiate persists key_mode = password on IssuerKey" do
      {:ok, {_ceremony, key, _shares, _participants, _transcript}} =
        create_ceremony("password", 1, 1, ["Alice"])

      assert key.key_mode == "password"
    end

    test "initiate rejects k >= 2 for password mode" do
      params = ceremony_params("password", 2, 3, ["Alice", "Bob", "Charlie"])

      assert {:error, :invalid_threshold} = CeremonyOrchestrator.initiate("ca-pw-bad", params)
    end

    test "end-to-end: exactly one share with n=1, k=1 after keygen" do
      {:ok, {ceremony, _key, _shares, _participants, _transcript}} =
        create_ceremony("password", 1, 1, ["Alice"])

      {:ok, _} = CeremonyOrchestrator.accept_share(ceremony.id, "Alice", "alice-pw")

      passwords = [{"Alice", "alice-pw"}]
      assert {:ok, _result} = CeremonyOrchestrator.execute_keygen(ceremony.id, passwords)

      {:ok, shares} = Repo.get_all_by_index(ThresholdShare, :issuer_key_id, ceremony.issuer_key_id)
      active_shares = Enum.filter(shares, &(&1.status == "active"))

      assert length(active_shares) == 1,
             "password mode should produce exactly 1 active share, got #{length(active_shares)}"

      [share] = active_shares
      assert share.total_shares == 1, "total_shares must be 1, got #{share.total_shares}"
      assert share.min_shares == 1, "min_shares must be 1, got #{share.min_shares}"
      assert share.encrypted_share != nil
      assert share.password_hash == nil
    end
  end

  # ---------------------------------------------------------------------------
  # single_custodian mode (same mechanics as password, n=1, k=1)
  # ---------------------------------------------------------------------------

  describe "key_mode: single_custodian" do
    test "initiate persists key_mode = single_custodian on IssuerKey" do
      {:ok, {_ceremony, key, _shares, _participants, _transcript}} =
        create_ceremony("single_custodian", 1, 1, ["Alice"])

      assert key.key_mode == "single_custodian"
    end

    test "initiate rejects k >= 2 for single_custodian mode" do
      params = ceremony_params("single_custodian", 2, 3, ["Alice", "Bob", "Charlie"])

      assert {:error, :invalid_threshold} =
               CeremonyOrchestrator.initiate("ca-sc-bad", params)
    end

    test "end-to-end: exactly one share with n=1, k=1 after keygen" do
      {:ok, {ceremony, _key, _shares, _participants, _transcript}} =
        create_ceremony("single_custodian", 1, 1, ["Alice"])

      {:ok, _} = CeremonyOrchestrator.accept_share(ceremony.id, "Alice", "alice-sc-pw")

      passwords = [{"Alice", "alice-sc-pw"}]
      assert {:ok, _result} = CeremonyOrchestrator.execute_keygen(ceremony.id, passwords)

      {:ok, shares} = Repo.get_all_by_index(ThresholdShare, :issuer_key_id, ceremony.issuer_key_id)
      active_shares = Enum.filter(shares, &(&1.status == "active"))

      assert length(active_shares) == 1,
             "single_custodian mode should produce exactly 1 active share, got #{length(active_shares)}"

      [share] = active_shares
      assert share.total_shares == 1, "total_shares must be 1, got #{share.total_shares}"
      assert share.min_shares == 1, "min_shares must be 1, got #{share.min_shares}"
      assert share.encrypted_share != nil
      assert share.password_hash == nil
    end
  end

  # ---------------------------------------------------------------------------
  # validate_key_mode gate
  # ---------------------------------------------------------------------------

  describe "validate_key_mode" do
    test "rejects an unknown key_mode" do
      params = ceremony_params("shamir_v2", 2, 3, ["Alice", "Bob", "Charlie"])

      assert {:error, {:invalid_key_mode, "shamir_v2"}} =
               CeremonyOrchestrator.initiate("ca-bad-mode", params)
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp ceremony_params(key_mode, threshold_k, threshold_n, custodian_names) do
    %{
      algorithm: "ECC-P256",
      threshold_k: threshold_k,
      threshold_n: threshold_n,
      custodian_names: custodian_names,
      auditor_name: "Auditor",
      is_root: true,
      ceremony_mode: :full,
      initiated_by: "Admin",
      key_alias: "key-#{key_mode}-#{threshold_n}",
      subject_dn: "/CN=Test #{key_mode} CA",
      key_mode: key_mode,
      keystore_mode: "software"
    }
  end

  defp create_ceremony(key_mode, threshold_k, threshold_n, custodian_names) do
    ca_id = "ca-km-#{key_mode}-#{:erlang.unique_integer([:positive])}"
    params = ceremony_params(key_mode, threshold_k, threshold_n, custodian_names)
    CeremonyOrchestrator.initiate(ca_id, params)
  end
end
