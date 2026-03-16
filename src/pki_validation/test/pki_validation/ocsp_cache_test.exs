defmodule PkiValidation.OcspCacheTest do
  use ExUnit.Case, async: true

  alias PkiValidation.OcspCache

  setup do
    table_name = :"ocsp_cache_test_#{System.unique_integer([:positive])}"
    {:ok, _pid} = OcspCache.start_link(name: nil, table_name: table_name)
    {:ok, table: table_name}
  end

  describe "get/1" do
    test "returns :miss for uncached serial", %{table: table} do
      assert :miss == OcspCache.get("NONEXISTENT", table)
    end

    test "returns cached value", %{table: table} do
      OcspCache.put("SERIAL001", %{status: "good"}, table: table)
      assert {:ok, %{status: "good"}} = OcspCache.get("SERIAL001", table)
    end

    test "returns :miss for expired entries", %{table: table} do
      OcspCache.put("SERIAL002", %{status: "good"}, table: table, ttl: 0)
      # TTL of 0 means it expires immediately
      Process.sleep(1)
      assert :miss == OcspCache.get("SERIAL002", table)
    end
  end

  describe "put/2" do
    test "stores value in cache", %{table: table} do
      assert :ok = OcspCache.put("SERIAL003", %{status: "revoked"}, table: table)
      assert {:ok, %{status: "revoked"}} = OcspCache.get("SERIAL003", table)
    end

    test "overwrites existing value", %{table: table} do
      OcspCache.put("SERIAL004", %{status: "good"}, table: table)
      OcspCache.put("SERIAL004", %{status: "revoked"}, table: table)
      assert {:ok, %{status: "revoked"}} = OcspCache.get("SERIAL004", table)
    end
  end

  describe "periodic cleanup" do
    test "expired entries are cleaned up by periodic cleanup", %{table: table} do
      # Insert entry with TTL of 0 so it expires immediately
      OcspCache.put("CLEANUP_TEST", %{status: "good"}, table: table, ttl: 0)
      Process.sleep(1)

      # Send cleanup message to the GenServer that owns the table
      # We need to find the process that owns this table
      owner = :ets.info(table, :owner)
      send(owner, :cleanup)
      Process.sleep(10)

      assert :miss == OcspCache.get("CLEANUP_TEST", table)
    end
  end

  describe "invalidate/1" do
    test "removes cached entry", %{table: table} do
      OcspCache.put("SERIAL005", %{status: "good"}, table: table)
      assert :ok = OcspCache.invalidate("SERIAL005", table)
      assert :miss == OcspCache.get("SERIAL005", table)
    end

    test "is no-op for nonexistent entry", %{table: table} do
      assert :ok = OcspCache.invalidate("NONEXISTENT", table)
    end
  end
end
