defmodule PkiMnesia.RepoTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.{Repo, TestHelper}
  alias PkiMnesia.Structs.CaInstance

  setup do
    dir = TestHelper.setup_mnesia()
    on_exit(fn -> TestHelper.teardown_mnesia(dir) end)
    :ok
  end

  test "insert and get a CaInstance" do
    ca = CaInstance.new(%{name: "Test Root CA", is_root: true})
    assert {:ok, ^ca} = Repo.insert(ca)

    fetched = Repo.get(CaInstance, ca.id)
    assert fetched.name == "Test Root CA"
    assert fetched.is_root == true
    assert fetched.id == ca.id
  end

  test "get returns nil for non-existent id" do
    assert Repo.get(CaInstance, "nonexistent-id") == nil
  end

  test "get_by returns struct by indexed field" do
    ca = CaInstance.new(%{name: "Unique CA", status: "active"})
    {:ok, _} = Repo.insert(ca)

    fetched = Repo.get_by(CaInstance, :name, "Unique CA")
    assert fetched.name == "Unique CA"
  end

  test "get_by returns nil when not found" do
    assert Repo.get_by(CaInstance, :name, "does not exist") == nil
  end

  test "update changes fields" do
    ca = CaInstance.new(%{name: "Before", status: "active"})
    {:ok, _} = Repo.insert(ca)

    {:ok, updated} = Repo.update(ca, %{name: "After", status: "suspended"})
    assert updated.name == "After"
    assert updated.status == "suspended"

    fetched = Repo.get(CaInstance, ca.id)
    assert fetched.name == "After"
  end

  test "update returns error for non-existent record" do
    ca = CaInstance.new(%{name: "Ghost"})
    assert {:error, :not_found} = Repo.update(ca, %{name: "Nope"})
  end

  test "delete removes a record" do
    ca = CaInstance.new(%{name: "Delete Me"})
    {:ok, _} = Repo.insert(ca)

    assert :ok = Repo.delete(CaInstance, ca.id)
    assert Repo.get(CaInstance, ca.id) == nil
  end

  test "all returns all records" do
    ca1 = CaInstance.new(%{name: "CA 1"})
    ca2 = CaInstance.new(%{name: "CA 2"})
    {:ok, _} = Repo.insert(ca1)
    {:ok, _} = Repo.insert(ca2)

    all = Repo.all(CaInstance)
    names = Enum.map(all, & &1.name) |> Enum.sort()
    assert names == ["CA 1", "CA 2"]
  end

  test "where filters records" do
    ca1 = CaInstance.new(%{name: "Active CA", status: "active"})
    ca2 = CaInstance.new(%{name: "Suspended CA", status: "suspended"})
    {:ok, _} = Repo.insert(ca1)
    {:ok, _} = Repo.insert(ca2)

    active = Repo.where(CaInstance, fn ca -> ca.status == "active" end)
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
    assert Repo.get(CaInstance, ca.id) != nil
  end
end
