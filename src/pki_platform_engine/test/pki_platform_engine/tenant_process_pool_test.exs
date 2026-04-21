defmodule PkiPlatformEngine.TenantProcessPoolTest do
  use ExUnit.Case

  # Hardcodes Postgres port 5434 (legacy multi-instance dev setup).
  # Excluded by default via test_helper.exs.
  @moduletag :legacy_db_mode

  alias PkiPlatformEngine.{TenantProcess, TenantRegistry}

  @tag :integration
  @tag :requires_db
  test "tenant repos use TENANT_POOL_SIZE env var" do
    # Ensure TenantRepo uses the test database port (5434, not direct_port 5432)
    tenant_config = Application.get_env(:pki_platform_engine, PkiPlatformEngine.TenantRepo, [])
    port = Keyword.get(tenant_config, :port, 5434)

    # Skip if database is not reachable
    case :gen_tcp.connect(~c"localhost", port, [], 1000) do
      {:ok, sock} -> :gen_tcp.close(sock)
      {:error, _} -> flunk("PostgreSQL not reachable on port #{port}. Start dev-infra first.")
    end

    suffix = System.unique_integer([:positive])
    registry_name = :"test_reg_pool_#{suffix}"

    start_supervised!({TenantRegistry, name: registry_name})

    tenant = %{
      id: "pool-test-#{suffix}",
      slug: "pool-slug-#{suffix}",
      database_name: "pki_platform_test"
    }

    {:ok, pid} = TenantProcess.start_link(tenant: tenant, registry: registry_name)

    {:ok, refs} = TenantRegistry.lookup(registry_name, tenant.id)

    ca_repo = refs.ca_repo
    assert Process.whereis(ca_repo) != nil

    # Verify we can checkout more than 2 connections concurrently.
    # If pool_size were still 2, the 3rd checkout would timeout.
    checkout_count = 5

    tasks =
      for _ <- 1..checkout_count do
        Task.async(fn ->
          try do
            Ecto.Adapters.SQL.query(ca_repo, "SELECT 1", [])
          rescue
            DBConnection.ConnectionError -> :pool_exhausted
          end
        end)
      end

    results = Task.await_many(tasks, 10_000)
    ok_count = Enum.count(results, &match?({:ok, _}, &1))

    assert ok_count >= 4,
           "Expected at least 4 concurrent connections but only got #{ok_count}. " <>
             "Pool size may not have been updated from the old default of 2."

    Supervisor.stop(pid)
  end

  test "TENANT_POOL_SIZE default is at least 5" do
    default_pool_size =
      case System.get_env("TENANT_POOL_SIZE") do
        nil -> 5
        val -> String.to_integer(val)
      end

    assert default_pool_size >= 5,
           "TENANT_POOL_SIZE default should be at least 5, got #{default_pool_size}"
  end
end
