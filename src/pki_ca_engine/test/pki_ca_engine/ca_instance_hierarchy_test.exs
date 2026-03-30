defmodule PkiCaEngine.CaInstanceHierarchyTest do
  use PkiCaEngine.DataCase, async: true

  alias PkiCaEngine.Schema.CaInstance

  @root_attrs %{name: "root-ca", status: "active", created_by: "admin"}
  @sub_attrs %{name: "sub-ca", status: "active", created_by: "admin"}

  describe "CA hierarchy" do
    test "changeset accepts parent_id" do
      parent_id = Uniq.UUID.uuid7()
      changeset = CaInstance.changeset(%CaInstance{}, Map.put(@sub_attrs, :parent_id, parent_id))
      assert changeset.valid?
      assert Ecto.Changeset.get_change(changeset, :parent_id) == parent_id
    end

    test "root CA has nil parent_id" do
      {:ok, root} = Repo.insert(CaInstance.changeset(%CaInstance{}, @root_attrs))
      assert root.parent_id == nil
    end

    test "can load children association" do
      {:ok, root} = Repo.insert(CaInstance.changeset(%CaInstance{}, @root_attrs))

      {:ok, sub} =
        Repo.insert(
          CaInstance.changeset(%CaInstance{}, Map.put(@sub_attrs, :parent_id, root.id))
        )

      root_with_children = Repo.preload(root, :children)
      assert length(root_with_children.children) == 1
      assert hd(root_with_children.children).id == sub.id
    end

    test "can load parent association" do
      {:ok, root} = Repo.insert(CaInstance.changeset(%CaInstance{}, @root_attrs))

      {:ok, sub} =
        Repo.insert(
          CaInstance.changeset(%CaInstance{}, Map.put(@sub_attrs, :parent_id, root.id))
        )

      sub_with_parent = Repo.preload(sub, :parent)
      assert sub_with_parent.parent.id == root.id
    end
  end
end
