defmodule PkiMnesia.ReplicationTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.{Schema, TestHelper}

  setup do
    dir = TestHelper.setup_mnesia()
    on_exit(fn -> TestHelper.teardown_mnesia(dir) end)
    :ok
  end

  describe "sync_tables/0" do
    test "returns 15 sync table names" do
      tables = Schema.sync_tables()
      assert length(tables) == 15
      assert :ca_instances in tables
      assert :issuer_keys in tables
      assert :threshold_shares in tables
      assert :key_ceremonies in tables
      assert :ceremony_participants in tables
      assert :ceremony_transcripts in tables
      assert :portal_users in tables
      assert :cert_profiles in tables
      assert :ra_instances in tables
      assert :ra_ca_connections in tables
      assert :api_keys in tables
      assert :dcv_challenges in tables
      assert :service_configs in tables
      assert :backup_records in tables
      assert :schema_versions in tables
    end
  end

  describe "async_tables/0" do
    test "returns 3 async table names" do
      tables = Schema.async_tables()
      assert length(tables) == 3
      assert :issued_certificates in tables
      assert :csr_requests in tables
      assert :certificate_status in tables
    end
  end

  describe "add_replica_copies/1" do
    test "function exists and has arity 1" do
      assert function_exported?(Schema, :add_replica_copies, 1)
    end

    test "returns error when primary node is unreachable" do
      result = Schema.add_replica_copies(:nonexistent_node@localhost)
      assert {:error, _reason} = result
    end
  end

  describe "promote_to_primary/0" do
    test "function exists and has arity 0" do
      assert function_exported?(Schema, :promote_to_primary, 0)
    end

    test "succeeds when tables are already disc_copies (already_exists case)" do
      # Tables created by setup are disc_copies; promote_to_primary should
      # handle the already_exists case gracefully and return :ok
      assert :ok = Schema.promote_to_primary()
    end
  end

  describe "demote_to_replica/1" do
    test "function exists and has arity 1" do
      assert function_exported?(Schema, :demote_to_replica, 1)
    end
  end
end
