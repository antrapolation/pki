defmodule PkiCaEngine.KeystoreManagementTest do
  use PkiCaEngine.DataCase, async: true

  alias PkiCaEngine.KeystoreManagement
  alias PkiCaEngine.Schema.{CaInstance, Keystore}

  setup do
    {:ok, ca} =
      Repo.insert(CaInstance.changeset(%CaInstance{}, %{name: "ks-test-ca", created_by: "admin"}))

    %{ca: ca}
  end

  # ── configure_keystore/2 ───────────────────────────────────────────

  describe "configure_keystore/2" do
    test "creates a software keystore for a CA instance", %{ca: ca} do
      attrs = %{type: "software", config: "raw-config-binary", provider_name: "SoftProvider"}

      assert {:ok, %Keystore{} = ks} = KeystoreManagement.configure_keystore(ca.id, attrs)
      assert ks.ca_instance_id == ca.id
      assert ks.type == "software"
      assert ks.config == "raw-config-binary"
      assert ks.provider_name == "SoftProvider"
      assert ks.status == "active"
    end

    test "creates an HSM keystore for a CA instance", %{ca: ca} do
      attrs = %{type: "hsm", config: "hsm-config-data", provider_name: "HsmProvider"}

      assert {:ok, %Keystore{} = ks} = KeystoreManagement.configure_keystore(ca.id, attrs)
      assert ks.type == "hsm"
    end

    test "rejects invalid keystore type", %{ca: ca} do
      attrs = %{type: "cloud", config: "some-config"}
      assert {:error, changeset} = KeystoreManagement.configure_keystore(ca.id, attrs)
      assert %{type: [_]} = errors_on(changeset)
    end

    test "rejects missing type", %{ca: ca} do
      attrs = %{config: "some-config"}
      assert {:error, changeset} = KeystoreManagement.configure_keystore(ca.id, attrs)
      assert %{type: ["can't be blank"]} = errors_on(changeset)
    end
  end

  # ── list_keystores/1 ───────────────────────────────────────────────

  describe "list_keystores/1" do
    test "returns all keystores for a CA instance", %{ca: ca} do
      {:ok, _} = KeystoreManagement.configure_keystore(ca.id, %{type: "software"})
      {:ok, _} = KeystoreManagement.configure_keystore(ca.id, %{type: "hsm"})

      keystores = KeystoreManagement.list_keystores(ca.id)
      assert length(keystores) == 2
    end

    test "returns empty list when no keystores exist", %{ca: ca} do
      assert KeystoreManagement.list_keystores(ca.id) == []
    end

    test "does not return keystores from other CA instances", %{ca: ca} do
      {:ok, other_ca} =
        Repo.insert(CaInstance.changeset(%CaInstance{}, %{name: "other-ks-ca", created_by: "admin"}))

      {:ok, _} = KeystoreManagement.configure_keystore(ca.id, %{type: "software"})
      {:ok, _} = KeystoreManagement.configure_keystore(other_ca.id, %{type: "hsm"})

      keystores = KeystoreManagement.list_keystores(ca.id)
      assert length(keystores) == 1
    end
  end

  # ── get_keystore/1 ─────────────────────────────────────────────────

  describe "get_keystore/1" do
    test "returns keystore by ID", %{ca: ca} do
      {:ok, created} = KeystoreManagement.configure_keystore(ca.id, %{type: "software"})
      assert {:ok, %Keystore{} = ks} = KeystoreManagement.get_keystore(created.id)
      assert ks.id == created.id
    end

    test "returns error for non-existent keystore" do
      assert {:error, :not_found} = KeystoreManagement.get_keystore(-1)
    end
  end

  # ── update_keystore/2 ──────────────────────────────────────────────

  describe "update_keystore/2" do
    test "updates config", %{ca: ca} do
      {:ok, ks} = KeystoreManagement.configure_keystore(ca.id, %{type: "software", config: "old"})
      assert {:ok, updated} = KeystoreManagement.update_keystore(ks.id, %{config: "new-config"})
      assert updated.config == "new-config"
    end

    test "updates status to inactive", %{ca: ca} do
      {:ok, ks} = KeystoreManagement.configure_keystore(ca.id, %{type: "software"})
      assert {:ok, updated} = KeystoreManagement.update_keystore(ks.id, %{status: "inactive"})
      assert updated.status == "inactive"
    end

    test "rejects invalid status", %{ca: ca} do
      {:ok, ks} = KeystoreManagement.configure_keystore(ca.id, %{type: "software"})
      assert {:error, changeset} = KeystoreManagement.update_keystore(ks.id, %{status: "deleted"})
      assert %{status: [_]} = errors_on(changeset)
    end

    test "returns error for non-existent keystore" do
      assert {:error, :not_found} = KeystoreManagement.update_keystore(-1, %{config: "x"})
    end
  end

  # ── available_keystores/1 ──────────────────────────────────────────

  describe "available_keystores/1" do
    test "returns only active keystores", %{ca: ca} do
      {:ok, _active} = KeystoreManagement.configure_keystore(ca.id, %{type: "software"})
      {:ok, inactive} = KeystoreManagement.configure_keystore(ca.id, %{type: "hsm"})
      {:ok, _} = KeystoreManagement.update_keystore(inactive.id, %{status: "inactive"})

      available = KeystoreManagement.available_keystores(ca.id)
      assert length(available) == 1
      assert hd(available).type == "software"
    end

    test "returns empty list when all keystores are inactive", %{ca: ca} do
      {:ok, ks} = KeystoreManagement.configure_keystore(ca.id, %{type: "software"})
      {:ok, _} = KeystoreManagement.update_keystore(ks.id, %{status: "inactive"})

      assert KeystoreManagement.available_keystores(ca.id) == []
    end
  end

  # ── get_provider_module/1 ──────────────────────────────────────────

  describe "get_provider_module/1" do
    test "maps software to StrapSoftPrivKeyStoreProvider" do
      assert KeystoreManagement.get_provider_module("software") == {:ok, "StrapSoftPrivKeyStoreProvider"}
    end

    test "maps hsm to StrapSofthsmPrivKeyStoreProvider" do
      assert KeystoreManagement.get_provider_module("hsm") == {:ok, "StrapSofthsmPrivKeyStoreProvider"}
    end

    test "returns error for unknown type" do
      assert {:error, :unknown_provider} = KeystoreManagement.get_provider_module("cloud")
    end
  end

  # ── Helper ─────────────────────────────────────────────────────────

  defp errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Regex.replace(~r"%{(\w+)}", message, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
