defmodule PkiReplicationTest do
  @moduledoc """
  Integration test verifying Mnesia replication functions work end-to-end
  on a single host. Tests Schema sync/async table lists and data persistence
  through promote_to_primary.
  """
  use ExUnit.Case, async: false

  alias PkiMnesia.{Schema, Repo, TestHelper}
  alias PkiMnesia.Structs.{IssuerKey, CaInstance}

  setup do
    dir = TestHelper.setup_mnesia()
    on_exit(fn -> TestHelper.teardown_mnesia(dir) end)
    :ok
  end

  test "sync tables list is complete" do
    sync = Schema.sync_tables()
    assert :issuer_keys in sync
    assert :threshold_shares in sync
    assert :ca_instances in sync
    assert :portal_users in sync
    assert :backup_records in sync
    assert :schema_versions in sync
    assert length(sync) == 18
  end

  test "async tables list is complete" do
    async = Schema.async_tables()
    assert :issued_certificates in async
    assert :csr_requests in async
    assert :certificate_status in async
    assert length(async) == 5
  end

  test "write to primary, verify data persists through promote_to_primary" do
    # Insert test data
    ca = CaInstance.new(%{name: "Replication Test CA", is_root: true})
    {:ok, _} = Repo.insert(ca)

    key = IssuerKey.new(%{
      ca_instance_id: ca.id,
      key_alias: "repl-test-key",
      algorithm: "ECC-P256"
    })
    {:ok, _} = Repo.insert(key)

    # Verify data exists
    {:ok, found_ca} = Repo.get(CaInstance, ca.id)
    assert found_ca.name == "Replication Test CA"

    {:ok, found_key} = Repo.get(IssuerKey, key.id)
    assert found_key.key_alias == "repl-test-key"

    # promote_to_primary should not lose data
    # (On a real replica this converts ram_copies to disc_copies;
    #  on a primary it's a no-op since tables are already disc_copies)
    :ok = Schema.promote_to_primary()

    # Data still there
    {:ok, still_ca} = Repo.get(CaInstance, ca.id)
    assert still_ca.name == "Replication Test CA"
  end

  test "full lifecycle: insert → promote → read → write post-promotion" do
    # Simulate a scenario: data written pre-promotion survives and
    # new data can be written post-promotion

    ca = CaInstance.new(%{name: "Pre-Promotion CA", is_root: true})
    {:ok, _} = Repo.insert(ca)

    :ok = Schema.promote_to_primary()

    # Write new data post-promotion
    key = IssuerKey.new(%{
      ca_instance_id: ca.id,
      key_alias: "post-promo-key",
      algorithm: "KAZ-SIGN-192"
    })
    {:ok, _} = Repo.insert(key)

    # Both pre and post data exist
    {:ok, all_cas} = Repo.all(CaInstance)
    assert length(all_cas) == 1

    {:ok, all_keys} = Repo.all(IssuerKey)
    assert length(all_keys) == 1
    assert hd(all_keys).algorithm == "KAZ-SIGN-192"
  end
end
