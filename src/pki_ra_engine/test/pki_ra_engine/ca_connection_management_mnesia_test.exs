defmodule PkiRaEngine.CaConnectionManagementMnesiaTest do
  @moduledoc "Mnesia-era tests for PkiRaEngine.CaConnectionManagement."
  use ExUnit.Case, async: false

  alias PkiMnesia.{Repo, TestHelper}
  alias PkiMnesia.Structs.IssuerKey
  alias PkiRaEngine.{CaConnectionManagement, RaInstanceManagement}

  setup do
    dir = TestHelper.setup_mnesia()
    on_exit(fn -> TestHelper.teardown_mnesia(dir) end)
    :ok
  end

  defp insert_ra!(name \\ "RA-#{System.unique_integer([:positive])}") do
    {:ok, ra} = RaInstanceManagement.create_ra_instance(%{name: name})
    ra
  end

  defp insert_issuer_key!(ca_instance_id) do
    key =
      IssuerKey.new(%{
        ca_instance_id: ca_instance_id,
        key_alias: "k-#{System.unique_integer([:positive])}",
        algorithm: "ML-DSA-65",
        status: "active",
        is_root: false
      })

    {:ok, inserted} = Repo.insert(key)
    inserted
  end

  describe "connect/2" do
    test "creates an active connection and derives ca_instance_id from the key" do
      ra = insert_ra!()
      key = insert_issuer_key!("ca-1")

      assert {:ok, conn} = CaConnectionManagement.connect(ra.id, %{issuer_key_id: key.id})
      assert conn.ra_instance_id == ra.id
      assert conn.ca_instance_id == "ca-1"
      assert conn.issuer_key_id == key.id
      assert conn.status == "active"
    end

    test "rejects blank ra_instance_id or issuer_key_id" do
      assert {:error, :ra_instance_required} =
               CaConnectionManagement.connect("", %{issuer_key_id: "anything"})

      assert {:error, :issuer_key_required} =
               CaConnectionManagement.connect("ra-1", %{})
    end

    test "rejects unknown issuer key" do
      ra = insert_ra!()

      assert {:error, :issuer_key_not_found} =
               CaConnectionManagement.connect(ra.id, %{issuer_key_id: "nope"})
    end

    test "rejects duplicate active connection for the same (ra, key) pair" do
      ra = insert_ra!()
      key = insert_issuer_key!("ca-x")

      {:ok, _} = CaConnectionManagement.connect(ra.id, %{issuer_key_id: key.id})

      assert {:error, :already_connected} =
               CaConnectionManagement.connect(ra.id, %{issuer_key_id: key.id})
    end
  end

  describe "disconnect/1" do
    test "flips status to revoked" do
      ra = insert_ra!()
      key = insert_issuer_key!("ca-y")
      {:ok, conn} = CaConnectionManagement.connect(ra.id, %{issuer_key_id: key.id})

      assert {:ok, revoked} = CaConnectionManagement.disconnect(conn.id)
      assert revoked.status == "revoked"
    end

    test "not_found for unknown id" do
      assert {:error, :not_found} = CaConnectionManagement.disconnect("nope")
    end
  end

  describe "list_connections + list_all_active + has_connections?" do
    test "list_connections/1 returns active rows for a specific ra only" do
      ra1 = insert_ra!("RA-A")
      ra2 = insert_ra!("RA-B")
      k1 = insert_issuer_key!("ca-a")
      k2 = insert_issuer_key!("ca-b")

      {:ok, _} = CaConnectionManagement.connect(ra1.id, %{issuer_key_id: k1.id})
      {:ok, c2} = CaConnectionManagement.connect(ra2.id, %{issuer_key_id: k2.id})
      {:ok, _} = CaConnectionManagement.disconnect(c2.id)

      assert [conn] = CaConnectionManagement.list_connections(ra1.id)
      assert conn.issuer_key_id == k1.id
      assert CaConnectionManagement.list_connections(ra2.id) == []
    end

    test "list_connected_issuer_keys + has_connections? return tenant-wide view" do
      ra = insert_ra!()
      k1 = insert_issuer_key!("ca-a")
      k2 = insert_issuer_key!("ca-b")

      refute CaConnectionManagement.has_connections?()

      {:ok, _} = CaConnectionManagement.connect(ra.id, %{issuer_key_id: k1.id})
      {:ok, _} = CaConnectionManagement.connect(ra.id, %{issuer_key_id: k2.id})

      assert CaConnectionManagement.has_connections?()
      ids = CaConnectionManagement.list_connected_issuer_keys() |> Enum.sort()
      assert ids == Enum.sort([k1.id, k2.id])
    end
  end
end
