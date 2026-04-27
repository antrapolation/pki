defmodule PkiAuditTrail.HashChainStoreTest do
  use ExUnit.Case, async: false

  alias PkiAuditTrail.HashChainStore

  @genesis String.duplicate("0", 64)

  setup do
    # ETS table is :public — clear it between tests for isolation.
    # HashChainStore is already started by the Application supervisor.
    if :ets.info(:pki_audit_hash_chain) != :undefined do
      :ets.delete_all_objects(:pki_audit_hash_chain)
    end
    :ok
  end

  test "returns genesis hash for tenant with no events" do
    tenant_id = Ecto.UUID.generate()
    assert HashChainStore.get_or_seed(tenant_id) == @genesis
  end

  test "caches in ETS after first call" do
    tenant_id = Ecto.UUID.generate()
    HashChainStore.get_or_seed(tenant_id)
    assert HashChainStore.get_or_seed(tenant_id) == @genesis
  end

  test "update stores new hash in ETS" do
    tenant_id = Ecto.UUID.generate()
    new_hash = String.duplicate("a", 64)
    HashChainStore.get_or_seed(tenant_id)
    :ok = HashChainStore.update(tenant_id, new_hash)
    assert HashChainStore.get_or_seed(tenant_id) == new_hash
  end

  test "different tenants have independent hashes" do
    t1 = Ecto.UUID.generate()
    t2 = Ecto.UUID.generate()
    HashChainStore.update(t1, String.duplicate("1", 64))
    HashChainStore.update(t2, String.duplicate("2", 64))
    assert HashChainStore.get_or_seed(t1) == String.duplicate("1", 64)
    assert HashChainStore.get_or_seed(t2) == String.duplicate("2", 64)
  end
end
