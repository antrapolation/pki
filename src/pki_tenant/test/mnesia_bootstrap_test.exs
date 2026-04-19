defmodule PkiTenant.MnesiaBootstrapTest do
  use ExUnit.Case, async: false

  @moduledoc """
  Tests for PkiTenant.MnesiaBootstrap replica mode branching.
  The primary (normal) boot path is implicitly tested via health_test.exs
  (TestHelper.setup_mnesia/0 exercises it). These tests focus on compile-time
  correctness and the conditional logic branches.
  """

  test "module compiles and exports start_link/1" do
    Code.ensure_loaded!(PkiTenant.MnesiaBootstrap)
    assert function_exported?(PkiTenant.MnesiaBootstrap, :start_link, 1)
  end

  test "module compiles and exports init/1" do
    Code.ensure_loaded!(PkiTenant.MnesiaBootstrap)
    assert function_exported?(PkiTenant.MnesiaBootstrap, :init, 1)
  end

  describe "replica mode guard" do
    test "REPLICA_MODE env var is not set in normal test runs" do
      # Ensure tests run with the primary (non-replica) code path
      refute System.get_env("REPLICA_MODE") == "true"
    end

    test "init_replica raises when PRIMARY_TENANT_NODE is missing" do
      # Set REPLICA_MODE to trigger replica path but omit PRIMARY_TENANT_NODE
      System.put_env("REPLICA_MODE", "true")
      System.delete_env("PRIMARY_TENANT_NODE")

      # start_link wraps init/1 — a raise inside init becomes {:error, reason}
      result = GenServer.start(PkiTenant.MnesiaBootstrap, [slug: "test-replica"])

      assert match?({:error, _}, result)

      # Reset — don't leak this into other tests
      System.delete_env("REPLICA_MODE")
    end
  end
end
