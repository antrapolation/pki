defmodule PkiCaEngine.CaInstanceManagementTest do
  use PkiCaEngine.DataCase, async: true

  alias PkiCaEngine.CaInstanceManagement
  alias PkiCaEngine.Schema.{CaInstance, IssuerKey}

  @root_attrs %{name: "root-ca", status: "active", created_by: "admin"}
  @sub_attrs %{name: "sub-ca", status: "active", created_by: "admin"}

  defp create_root!(attrs \\ @root_attrs) do
    {:ok, root} = Repo.insert(CaInstance.changeset(%CaInstance{}, attrs))
    root
  end

  defp create_sub!(parent, attrs \\ @sub_attrs) do
    {:ok, sub} =
      Repo.insert(CaInstance.changeset(%CaInstance{}, Map.put(attrs, :parent_id, parent.id)))

    sub
  end

  defp create_issuer_key!(ca, key_alias, status \\ "pending") do
    {:ok, key} =
      Repo.insert(
        IssuerKey.changeset(%IssuerKey{}, %{
          ca_instance_id: ca.id,
          key_alias: key_alias,
          algorithm: "ML-DSA-65",
          status: status
        })
      )

    key
  end

  describe "create_ca_instance/2" do
    test "creates root CA (no parent)" do
      assert {:ok, ca} = CaInstanceManagement.create_ca_instance(@root_attrs)
      assert ca.parent_id == nil
      assert ca.name == "root-ca"
    end

    test "creates sub-CA under root" do
      root = create_root!()

      assert {:ok, sub} =
               CaInstanceManagement.create_ca_instance(Map.put(@sub_attrs, :parent_id, root.id))

      assert sub.parent_id == root.id
    end

    test "allows arbitrary depth hierarchy" do
      root = create_root!()
      sub = create_sub!(root)

      assert {:ok, deep} =
               CaInstanceManagement.create_ca_instance(
                 %{name: "deep-ca", status: "active", created_by: "admin", parent_id: sub.id}
               )

      assert deep.parent_id == sub.id
    end

    test "returns :parent_not_found for invalid parent_id" do
      assert {:error, :parent_not_found} =
               CaInstanceManagement.create_ca_instance(%{
                 name: "orphan",
                 status: "active",
                 created_by: "admin",
                 parent_id: Uniq.UUID.uuid7()
               })
    end
  end

  describe "get_ca_instance/1" do
    test "returns CA with preloaded children and issuer_keys" do
      root = create_root!()
      sub = create_sub!(root)
      create_issuer_key!(root, "root-key")

      assert {:ok, ca} = CaInstanceManagement.get_ca_instance(root.id)
      assert length(ca.children) == 1
      assert hd(ca.children).id == sub.id
      assert length(ca.issuer_keys) == 1
    end

    test "returns :not_found for missing id" do
      assert {:error, :not_found} = CaInstanceManagement.get_ca_instance(Uniq.UUID.uuid7())
    end
  end

  describe "is_root?/1" do
    test "returns true for root CA" do
      root = create_root!()
      assert CaInstanceManagement.is_root?(root) == true
    end

    test "returns false for sub-CA" do
      root = create_root!()
      sub = create_sub!(root)
      assert CaInstanceManagement.is_root?(sub) == false
    end
  end

  describe "is_leaf?/1" do
    test "returns true for CA with no children" do
      root = create_root!()
      assert CaInstanceManagement.is_leaf?(root) == true
    end

    test "returns false for CA with children" do
      root = create_root!()
      _sub = create_sub!(root)
      assert CaInstanceManagement.is_leaf?(root) == false
    end
  end

  describe "depth/1" do
    test "root has depth 1" do
      root = create_root!()
      assert CaInstanceManagement.depth(root) == 1
    end

    test "sub-CA has depth 2" do
      root = create_root!()
      sub = create_sub!(root)
      assert CaInstanceManagement.depth(sub) == 2
    end

    test "third-level CA has depth 3" do
      root = create_root!()
      sub = create_sub!(root)

      {:ok, deep} =
        Repo.insert(
          CaInstance.changeset(%CaInstance{}, %{
            name: "deep-ca",
            status: "active",
            created_by: "admin",
            parent_id: sub.id
          })
        )

      assert CaInstanceManagement.depth(deep) == 3
    end
  end

  describe "role/1" do
    test "returns :root for root-only CA" do
      root = create_root!()
      assert CaInstanceManagement.role(root) == :root
    end

    test "returns :root for root with children" do
      root = create_root!()
      _sub = create_sub!(root)
      assert CaInstanceManagement.role(root) == :root
    end

    test "returns :issuing for leaf sub-CA" do
      root = create_root!()
      sub = create_sub!(root)
      assert CaInstanceManagement.role(sub) == :issuing
    end

    test "returns :intermediate for mid-level CA" do
      root = create_root!()
      sub = create_sub!(root)

      _deep =
        Repo.insert!(
          CaInstance.changeset(%CaInstance{}, %{
            name: "deep-ca",
            status: "active",
            created_by: "admin",
            parent_id: sub.id
          })
        )

      assert CaInstanceManagement.role(sub) == :intermediate
    end
  end

  describe "list_hierarchy/0" do
    test "returns root CAs with children preloaded" do
      root = create_root!()
      sub = create_sub!(root)

      hierarchy = CaInstanceManagement.list_hierarchy()
      assert length(hierarchy) == 1

      root_ca = hd(hierarchy)
      assert root_ca.id == root.id
      assert length(root_ca.children) == 1
      assert hd(root_ca.children).id == sub.id
    end

    test "returns empty list when no CAs exist" do
      assert CaInstanceManagement.list_hierarchy() == []
    end
  end

  describe "update_status/2" do
    test "updates CA instance status" do
      root = create_root!()
      assert {:ok, updated} = CaInstanceManagement.update_status(root.id, "suspended")
      assert updated.status == "suspended"
    end

    test "returns :not_found for missing CA" do
      assert {:error, :not_found} =
               CaInstanceManagement.update_status(Uniq.UUID.uuid7(), "active")
    end
  end

  describe "leaf_ca_issuer_keys/0" do
    test "returns only keys from leaf CAs" do
      root = create_root!()
      sub = create_sub!(root)

      _root_key = create_issuer_key!(root, "root-key")
      leaf_key = create_issuer_key!(sub, "sub-key")

      keys = CaInstanceManagement.leaf_ca_issuer_keys()
      assert length(keys) == 1
      assert hd(keys).id == leaf_key.id
    end

    test "returns keys from standalone root (which is a leaf)" do
      root = create_root!()
      key = create_issuer_key!(root, "root-key")

      keys = CaInstanceManagement.leaf_ca_issuer_keys()
      assert length(keys) == 1
      assert hd(keys).id == key.id
    end
  end

  describe "active_leaf_issuer_keys/0" do
    test "returns only active keys from leaf CAs" do
      root = create_root!()
      sub = create_sub!(root)

      _pending_key = create_issuer_key!(sub, "pending-key", "pending")
      active_key = create_issuer_key!(sub, "active-key", "active")

      keys = CaInstanceManagement.active_leaf_issuer_keys()
      assert length(keys) == 1
      assert hd(keys).id == active_key.id
    end

    test "returns empty list when no active leaf keys exist" do
      root = create_root!()
      _sub = create_sub!(root)
      create_issuer_key!(root, "root-key", "active")

      keys = CaInstanceManagement.active_leaf_issuer_keys()
      assert keys == []
    end
  end
end
