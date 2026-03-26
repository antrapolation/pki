defmodule PkiCaEngine.KeyCeremony.ThresholdValidationTest do
  @moduledoc """
  Edge case tests for ceremony threshold validation (UC-CA-29).

  The threshold scheme requires:
    - K >= 2 (minimum number of shares to reconstruct)
    - K <= N (K cannot exceed total custodian count)
    - Both K and N must be positive integers

  This module exhaustively tests boundary conditions.
  """
  use PkiCaEngine.DataCase, async: true

  alias PkiCaEngine.KeyCeremony.SyncCeremony
  alias PkiCaEngine.Schema.{CaInstance, CaUser, Keystore}

  setup do
    {:ok, ca} =
      Repo.insert(CaInstance.changeset(%CaInstance{}, %{
        name: "threshold-ca-#{System.unique_integer([:positive])}",
        created_by: "admin"
      }))

    {:ok, keystore} =
      Repo.insert(Keystore.changeset(%Keystore{}, %{ca_instance_id: ca.id, type: "software"}))

    {:ok, initiator} =
      Repo.insert(CaUser.changeset(%CaUser{}, %{
        ca_instance_id: ca.id,
        role: "key_manager"
      }))

    %{ca: ca, keystore: keystore, initiator: initiator}
  end

  defp ceremony_params(ctx, k, n) do
    %{
      algorithm: "RSA-4096",
      keystore_id: ctx.keystore.id,
      threshold_k: k,
      threshold_n: n,
      initiated_by: ctx.initiator.id
    }
  end

  # ── Invalid threshold values ────────────────────────────────────────────

  describe "invalid threshold parameters" do
    test "K=1, N=3 fails (K must be >= 2)", ctx do
      params = ceremony_params(ctx, 1, 3)
      assert {:error, :invalid_threshold} = SyncCeremony.initiate(ctx.ca.id, params)
    end

    test "K=4, N=3 fails (K must be <= N)", ctx do
      params = ceremony_params(ctx, 4, 3)
      assert {:error, :invalid_threshold} = SyncCeremony.initiate(ctx.ca.id, params)
    end

    test "K=0, N=0 fails", ctx do
      params = ceremony_params(ctx, 0, 0)
      assert {:error, :invalid_threshold} = SyncCeremony.initiate(ctx.ca.id, params)
    end

    test "K=0, N=3 fails (K must be >= 2)", ctx do
      params = ceremony_params(ctx, 0, 3)
      assert {:error, :invalid_threshold} = SyncCeremony.initiate(ctx.ca.id, params)
    end

    test "K=1, N=1 fails (K must be >= 2)", ctx do
      params = ceremony_params(ctx, 1, 1)
      assert {:error, :invalid_threshold} = SyncCeremony.initiate(ctx.ca.id, params)
    end

    test "K=-1, N=3 fails (negative K)", ctx do
      params = ceremony_params(ctx, -1, 3)
      assert {:error, :invalid_threshold} = SyncCeremony.initiate(ctx.ca.id, params)
    end

    test "K=2, N=-1 fails (negative N)", ctx do
      params = ceremony_params(ctx, 2, -1)
      assert {:error, :invalid_threshold} = SyncCeremony.initiate(ctx.ca.id, params)
    end

    test "K=10, N=5 fails (K exceeds N)", ctx do
      params = ceremony_params(ctx, 10, 5)
      assert {:error, :invalid_threshold} = SyncCeremony.initiate(ctx.ca.id, params)
    end
  end

  # ── Valid threshold values ──────────────────────────────────────────────

  describe "valid threshold parameters" do
    test "K=2, N=2 succeeds (minimum valid configuration)", ctx do
      params = ceremony_params(ctx, 2, 2)
      assert {:ok, {ceremony, issuer_key}} = SyncCeremony.initiate(ctx.ca.id, params)

      assert ceremony.threshold_k == 2
      assert ceremony.threshold_n == 2
      assert issuer_key.status == "pending"
    end

    test "K=5, N=5 succeeds (K equals N)", ctx do
      params = ceremony_params(ctx, 5, 5)
      assert {:ok, {ceremony, issuer_key}} = SyncCeremony.initiate(ctx.ca.id, params)

      assert ceremony.threshold_k == 5
      assert ceremony.threshold_n == 5
      assert issuer_key.status == "pending"
    end

    test "K=2, N=3 succeeds (standard configuration)", ctx do
      params = ceremony_params(ctx, 2, 3)
      assert {:ok, {ceremony, _issuer_key}} = SyncCeremony.initiate(ctx.ca.id, params)

      assert ceremony.threshold_k == 2
      assert ceremony.threshold_n == 3
    end

    test "K=3, N=5 succeeds (common real-world configuration)", ctx do
      params = ceremony_params(ctx, 3, 5)
      assert {:ok, {ceremony, _issuer_key}} = SyncCeremony.initiate(ctx.ca.id, params)

      assert ceremony.threshold_k == 3
      assert ceremony.threshold_n == 5
    end

    test "K=2, N=10 succeeds (low threshold, many custodians)", ctx do
      params = ceremony_params(ctx, 2, 10)
      assert {:ok, {ceremony, _issuer_key}} = SyncCeremony.initiate(ctx.ca.id, params)

      assert ceremony.threshold_k == 2
      assert ceremony.threshold_n == 10
    end
  end

  # ── Boundary values ─────────────────────────────────────────────────────

  describe "boundary values" do
    test "K=2 is the minimum valid K", ctx do
      # K=1 should fail
      assert {:error, :invalid_threshold} =
               SyncCeremony.initiate(ctx.ca.id, ceremony_params(ctx, 1, 2))

      # K=2 should succeed
      assert {:ok, _} =
               SyncCeremony.initiate(ctx.ca.id, ceremony_params(ctx, 2, 2))
    end

    test "K=N is the maximum valid K for a given N", ctx do
      # K=N should succeed
      assert {:ok, _} =
               SyncCeremony.initiate(ctx.ca.id, ceremony_params(ctx, 3, 3))

      # K=N+1 should fail
      assert {:error, :invalid_threshold} =
               SyncCeremony.initiate(ctx.ca.id, ceremony_params(ctx, 4, 3))
    end

    test "threshold config is stored on the issuer key", ctx do
      params = ceremony_params(ctx, 3, 5)
      {:ok, {_ceremony, issuer_key}} = SyncCeremony.initiate(ctx.ca.id, params)

      assert issuer_key.threshold_config == %{k: 3, n: 5}
    end
  end
end
