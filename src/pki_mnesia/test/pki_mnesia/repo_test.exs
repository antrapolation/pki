defmodule PkiMnesia.RepoTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.{Repo, TestHelper}
  alias PkiMnesia.Structs.{CaInstance, IssuerKey, ThresholdShare}

  setup do
    dir = TestHelper.setup_mnesia()
    on_exit(fn -> TestHelper.teardown_mnesia(dir) end)
    :ok
  end

  test "insert and get a CaInstance" do
    ca = CaInstance.new(%{name: "Test Root CA", is_root: true})
    assert {:ok, ^ca} = Repo.insert(ca)

    assert {:ok, fetched} = Repo.get(CaInstance, ca.id)
    assert fetched.name == "Test Root CA"
    assert fetched.is_root == true
    assert fetched.id == ca.id
  end

  test "get returns {:ok, nil} for non-existent id" do
    assert {:ok, nil} = Repo.get(CaInstance, "nonexistent-id")
  end

  test "get_by returns struct by indexed field" do
    ca = CaInstance.new(%{name: "Unique CA", status: "active"})
    {:ok, _} = Repo.insert(ca)

    assert {:ok, fetched} = Repo.get_by(CaInstance, :name, "Unique CA")
    assert fetched.name == "Unique CA"
  end

  test "get_by returns {:ok, nil} when not found" do
    assert {:ok, nil} = Repo.get_by(CaInstance, :name, "does not exist")
  end

  test "update changes fields" do
    ca = CaInstance.new(%{name: "Before", status: "active"})
    {:ok, _} = Repo.insert(ca)

    {:ok, updated} = Repo.update(ca, %{name: "After", status: "suspended"})
    assert updated.name == "After"
    assert updated.status == "suspended"

    assert {:ok, fetched} = Repo.get(CaInstance, ca.id)
    assert fetched.name == "After"
  end

  test "update returns error for non-existent record" do
    ca = CaInstance.new(%{name: "Ghost"})
    assert {:error, :not_found} = Repo.update(ca, %{name: "Nope"})
  end

  test "delete removes a record" do
    ca = CaInstance.new(%{name: "Delete Me"})
    {:ok, _} = Repo.insert(ca)

    assert {:ok, _} = Repo.delete(CaInstance, ca.id)
    assert {:ok, nil} = Repo.get(CaInstance, ca.id)
  end

  test "all returns all records" do
    ca1 = CaInstance.new(%{name: "CA 1"})
    ca2 = CaInstance.new(%{name: "CA 2"})
    {:ok, _} = Repo.insert(ca1)
    {:ok, _} = Repo.insert(ca2)

    assert {:ok, all} = Repo.all(CaInstance)
    names = Enum.map(all, & &1.name) |> Enum.sort()
    assert names == ["CA 1", "CA 2"]
  end

  test "where filters records" do
    ca1 = CaInstance.new(%{name: "Active CA", status: "active"})
    ca2 = CaInstance.new(%{name: "Suspended CA", status: "suspended"})
    {:ok, _} = Repo.insert(ca1)
    {:ok, _} = Repo.insert(ca2)

    assert {:ok, active} = Repo.where(CaInstance, fn ca -> ca.status == "active" end)
    assert length(active) == 1
    assert hd(active).name == "Active CA"
  end

  test "transaction executes atomically" do
    ca = CaInstance.new(%{name: "Txn CA"})

    {:ok, result} = Repo.transaction(fn ->
      table = PkiMnesia.Schema.table_name(CaInstance)
      record = PkiMnesia.Repo.struct_to_record(table, ca)
      :mnesia.write(record)
      :wrote_it
    end)

    assert result == :wrote_it
    assert {:ok, fetched} = Repo.get(CaInstance, ca.id)
    assert fetched != nil
  end

  # D9: Round-trip tests for IssuerKey (has :algorithm before :id alphabetically)
  test "insert and get IssuerKey round-trip preserves all fields" do
    key = IssuerKey.new(%{
      ca_instance_id: "ca-123",
      key_alias: "root-key-1",
      algorithm: "ML-DSA-65",
      status: "active",
      is_root: true,
      ceremony_mode: :full,
      subject_dn: "CN=Test Root CA",
      threshold_config: %{k: 2, n: 3}
    })

    assert {:ok, _} = Repo.insert(key)
    assert {:ok, fetched} = Repo.get(IssuerKey, key.id)

    assert fetched.id == key.id
    assert fetched.ca_instance_id == "ca-123"
    assert fetched.key_alias == "root-key-1"
    assert fetched.algorithm == "ML-DSA-65"
    assert fetched.status == "active"
    assert fetched.is_root == true
    assert fetched.ceremony_mode == :full
    assert fetched.subject_dn == "CN=Test Root CA"
    assert fetched.threshold_config == %{k: 2, n: 3}
  end

  # D9: Round-trip tests for ThresholdShare
  test "insert and get ThresholdShare round-trip preserves all fields" do
    share = ThresholdShare.new(%{
      issuer_key_id: "key-456",
      custodian_name: "Alice",
      share_index: 1,
      encrypted_share: <<1, 2, 3, 4>>,
      password_hash: "$2b$12$fakehash",
      min_shares: 2,
      total_shares: 3,
      status: "active"
    })

    assert {:ok, _} = Repo.insert(share)
    assert {:ok, fetched} = Repo.get(ThresholdShare, share.id)

    assert fetched.id == share.id
    assert fetched.issuer_key_id == "key-456"
    assert fetched.custodian_name == "Alice"
    assert fetched.share_index == 1
    assert fetched.encrypted_share == <<1, 2, 3, 4>>
    assert fetched.password_hash == "$2b$12$fakehash"
    assert fetched.min_shares == 2
    assert fetched.total_shares == 3
    assert fetched.status == "active"
  end
end
