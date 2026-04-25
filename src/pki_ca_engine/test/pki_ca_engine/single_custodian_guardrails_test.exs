defmodule PkiCaEngine.SingleCustodianGuardrailsTest do
  @moduledoc """
  Tests for E1.8 single-custodian guardrails:

  1. `initiate` with key_role: "root", key_mode: "password" → {:error, :root_requires_threshold}
  2. `initiate` with key_role: "issuing_sub", key_mode: "single_custodian" → succeeds
  3. `initiate` with key_role: "root", key_mode: "threshold" → succeeds
  4. key_role field defaults to "operational_sub" when not supplied
  5. key_role is persisted on IssuerKey
  """
  use ExUnit.Case, async: false

  alias PkiMnesia.{TestHelper, Repo}
  alias PkiMnesia.Structs.IssuerKey
  alias PkiCaEngine.CeremonyOrchestrator

  setup do
    dir = TestHelper.setup_mnesia()

    on_exit(fn ->
      TestHelper.teardown_mnesia(dir)
    end)

    :ok
  end

  # ---------------------------------------------------------------------------
  # Test 1: root + non-threshold → {:error, :root_requires_threshold}
  # ---------------------------------------------------------------------------

  describe "root key_role guardrail" do
    test "initiate rejects root key_role with key_mode=password" do
      params = ceremony_params(%{key_role: "root", key_mode: "password", threshold_k: 1, threshold_n: 1, custodian_names: ["Alice"]})

      assert {:error, :root_requires_threshold} =
               CeremonyOrchestrator.initiate("ca-guardrail-root-pw", params)
    end

    test "initiate rejects root key_role with key_mode=single_custodian" do
      params = ceremony_params(%{key_role: "root", key_mode: "single_custodian", threshold_k: 1, threshold_n: 1, custodian_names: ["Alice"]})

      assert {:error, :root_requires_threshold} =
               CeremonyOrchestrator.initiate("ca-guardrail-root-sc", params)
    end

    # Test 3 from task spec: root + threshold → succeeds
    test "initiate allows root key_role with key_mode=threshold" do
      params = ceremony_params(%{key_role: "root", key_mode: "threshold", threshold_k: 2, threshold_n: 3, custodian_names: ["Alice", "Bob", "Charlie"]})

      assert {:ok, {_ceremony, key, _shares, _participants, _transcript}} =
               CeremonyOrchestrator.initiate("ca-guardrail-root-thr", params)

      assert key.key_role == "root"
    end
  end

  # ---------------------------------------------------------------------------
  # Test 2: issuing_sub + single_custodian → succeeds
  # ---------------------------------------------------------------------------

  describe "non-root key_role with non-threshold modes" do
    test "initiate allows issuing_sub key_role with key_mode=single_custodian" do
      params = ceremony_params(%{key_role: "issuing_sub", key_mode: "single_custodian", threshold_k: 1, threshold_n: 1, custodian_names: ["Alice"]})

      assert {:ok, {_ceremony, key, _shares, _participants, _transcript}} =
               CeremonyOrchestrator.initiate("ca-guardrail-isub-sc", params)

      assert key.key_role == "issuing_sub"
      assert key.key_mode == "single_custodian"
    end

    test "initiate allows operational_sub key_role with key_mode=password" do
      params = ceremony_params(%{key_role: "operational_sub", key_mode: "password", threshold_k: 1, threshold_n: 1, custodian_names: ["Alice"]})

      assert {:ok, {_ceremony, key, _shares, _participants, _transcript}} =
               CeremonyOrchestrator.initiate("ca-guardrail-opsub-pw", params)

      assert key.key_role == "operational_sub"
      assert key.key_mode == "password"
    end
  end

  # ---------------------------------------------------------------------------
  # key_role defaults and persistence
  # ---------------------------------------------------------------------------

  describe "key_role field" do
    test "defaults to operational_sub when not supplied" do
      params =
        ceremony_params(%{key_mode: "threshold", threshold_k: 2, threshold_n: 3, custodian_names: ["Alice", "Bob", "Charlie"]})
        |> Map.delete(:key_role)

      assert {:ok, {_ceremony, key, _shares, _participants, _transcript}} =
               CeremonyOrchestrator.initiate("ca-guardrail-default-role", params)

      assert key.key_role == "operational_sub"
    end

    test "key_role is persisted to IssuerKey in Mnesia" do
      params = ceremony_params(%{key_role: "issuing_sub", key_mode: "threshold", threshold_k: 2, threshold_n: 3, custodian_names: ["Alice", "Bob", "Charlie"]})

      {:ok, {_ceremony, key, _shares, _participants, _transcript}} =
        CeremonyOrchestrator.initiate("ca-guardrail-persist", params)

      # Read back from Mnesia and verify persistence
      {:ok, stored_key} = Repo.get(IssuerKey, key.id)
      assert stored_key.key_role == "issuing_sub"
    end

    test "rejects invalid key_role" do
      params = ceremony_params(%{key_role: "superuser", key_mode: "threshold", threshold_k: 2, threshold_n: 3, custodian_names: ["Alice", "Bob", "Charlie"]})

      assert {:error, {:invalid_key_role, "superuser"}} =
               CeremonyOrchestrator.initiate("ca-guardrail-bad-role", params)
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp ceremony_params(overrides) do
    defaults = %{
      algorithm: "ECC-P256",
      threshold_k: 2,
      threshold_n: 3,
      custodian_names: ["Alice", "Bob", "Charlie"],
      auditor_name: "External Auditor",
      is_root: false,
      ceremony_mode: :full,
      initiated_by: "Admin",
      key_alias: "guardrail-test-#{:erlang.unique_integer([:positive])}",
      subject_dn: "/CN=Guardrail Test CA",
      key_mode: "threshold",
      key_role: "operational_sub",
      keystore_mode: "software"
    }

    Map.merge(defaults, overrides)
  end
end
