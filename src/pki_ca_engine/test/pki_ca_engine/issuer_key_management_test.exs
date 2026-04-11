defmodule PkiCaEngine.IssuerKeyManagementTest do
  use PkiCaEngine.DataCase, async: true

  alias PkiCaEngine.IssuerKeyManagement
  alias PkiCaEngine.Schema.{CaInstance, IssuerKey, Keystore}

  setup do
    {:ok, ca} =
      Repo.insert(CaInstance.changeset(%CaInstance{}, %{name: "ik-test-ca", created_by: "admin"}))

    {:ok, keystore} =
      Repo.insert(Keystore.changeset(%Keystore{}, %{ca_instance_id: ca.id, type: "software"}))

    %{ca: ca, keystore: keystore}
  end

  # ── create_issuer_key/2 ───────────────────────────────────────────

  describe "create_issuer_key/2" do
    test "creates an issuer key with valid attributes", %{ca: ca, keystore: keystore} do
      attrs = %{
        key_alias: "root-key-1",
        algorithm: "RSA-4096",
        is_root: true,
        keystore_ref: "ks-ref-#{keystore.id}"
      }

      assert {:ok, %IssuerKey{} = key} = IssuerKeyManagement.create_issuer_key(nil, ca.id, attrs)
      assert key.ca_instance_id == ca.id
      assert key.key_alias == "root-key-1"
      assert key.algorithm == "RSA-4096"
      assert key.is_root == true
      assert key.status == "pending"
      assert key.keystore_ref == "ks-ref-#{keystore.id}"
    end

    test "defaults status to pending", %{ca: ca} do
      attrs = %{key_alias: "sub-key-1", algorithm: "EC-P256"}

      assert {:ok, %IssuerKey{} = key} = IssuerKeyManagement.create_issuer_key(nil, ca.id, attrs)
      assert key.status == "pending"
    end

    test "defaults is_root to false", %{ca: ca} do
      attrs = %{key_alias: "sub-key-2", algorithm: "EC-P256"}

      assert {:ok, %IssuerKey{} = key} = IssuerKeyManagement.create_issuer_key(nil, ca.id, attrs)
      assert key.is_root == false
    end

    test "rejects missing key_alias", %{ca: ca} do
      attrs = %{algorithm: "RSA-4096"}
      assert {:error, changeset} = IssuerKeyManagement.create_issuer_key(nil, ca.id, attrs)
      assert %{key_alias: ["can't be blank"]} = errors_on(changeset)
    end

    test "rejects missing algorithm", %{ca: ca} do
      attrs = %{key_alias: "my-key"}
      assert {:error, changeset} = IssuerKeyManagement.create_issuer_key(nil, ca.id, attrs)
      assert %{algorithm: ["can't be blank"]} = errors_on(changeset)
    end

    test "enforces unique key_alias per CA instance", %{ca: ca} do
      attrs = %{key_alias: "dup-key", algorithm: "RSA-4096"}
      assert {:ok, _} = IssuerKeyManagement.create_issuer_key(nil, ca.id, attrs)
      assert {:error, changeset} = IssuerKeyManagement.create_issuer_key(nil, ca.id, attrs)
      assert %{ca_instance_id: _} = errors_on(changeset)
    end
  end

  # ── get_issuer_key/1 ─────────────────────────────────────────────

  describe "get_issuer_key/1" do
    test "returns issuer key by ID", %{ca: ca} do
      {:ok, created} =
        IssuerKeyManagement.create_issuer_key(nil, ca.id, %{key_alias: "get-key", algorithm: "RSA-4096"})

      assert {:ok, %IssuerKey{} = key} = IssuerKeyManagement.get_issuer_key(nil, created.id)
      assert key.id == created.id
      assert key.key_alias == "get-key"
    end

    test "returns error for non-existent key" do
      assert {:error, :not_found} = IssuerKeyManagement.get_issuer_key(nil, Uniq.UUID.uuid7())
    end
  end

  # ── list_issuer_keys/1 ──────────────────────────────────────────

  describe "list_issuer_keys/1" do
    test "returns all issuer keys for a CA instance", %{ca: ca} do
      {:ok, _} = IssuerKeyManagement.create_issuer_key(nil, ca.id, %{key_alias: "k1", algorithm: "RSA-4096"})
      {:ok, _} = IssuerKeyManagement.create_issuer_key(nil, ca.id, %{key_alias: "k2", algorithm: "EC-P256"})

      keys = IssuerKeyManagement.list_issuer_keys(nil, ca.id)
      assert length(keys) == 2
    end

    test "returns empty list when no keys exist", %{ca: ca} do
      assert IssuerKeyManagement.list_issuer_keys(nil, ca.id) == []
    end

    test "does not return keys from other CA instances", %{ca: ca} do
      {:ok, other_ca} =
        Repo.insert(CaInstance.changeset(%CaInstance{}, %{name: "other-ik-ca", created_by: "admin"}))

      {:ok, _} = IssuerKeyManagement.create_issuer_key(nil, ca.id, %{key_alias: "k1", algorithm: "RSA-4096"})
      {:ok, _} = IssuerKeyManagement.create_issuer_key(nil, other_ca.id, %{key_alias: "k2", algorithm: "EC-P256"})

      keys = IssuerKeyManagement.list_issuer_keys(nil, ca.id)
      assert length(keys) == 1
      assert hd(keys).key_alias == "k1"
    end

    test "filters by status", %{ca: ca} do
      {:ok, k1} = IssuerKeyManagement.create_issuer_key(nil, ca.id, %{key_alias: "k1", algorithm: "RSA-4096"})
      {:ok, _k2} = IssuerKeyManagement.create_issuer_key(nil, ca.id, %{key_alias: "k2", algorithm: "EC-P256"})

      # Activate k1
      {:ok, _} = IssuerKeyManagement.update_status(nil, k1, "active")

      active_keys = IssuerKeyManagement.list_issuer_keys(nil, ca.id, status: "active")
      assert length(active_keys) == 1
      assert hd(active_keys).key_alias == "k1"

      pending_keys = IssuerKeyManagement.list_issuer_keys(nil, ca.id, status: "pending")
      assert length(pending_keys) == 1
      assert hd(pending_keys).key_alias == "k2"
    end
  end

  # ── update_status/2 ─────────────────────────────────────────────

  describe "update_status/2" do
    test "pending → active is valid", %{ca: ca} do
      {:ok, key} = IssuerKeyManagement.create_issuer_key(nil, ca.id, %{key_alias: "s1", algorithm: "RSA-4096"})
      assert {:ok, updated} = IssuerKeyManagement.update_status(nil, key,"active")
      assert updated.status == "active"
    end

    test "active → suspended is valid", %{ca: ca} do
      {:ok, key} = IssuerKeyManagement.create_issuer_key(nil, ca.id, %{key_alias: "s2", algorithm: "RSA-4096"})
      {:ok, key} = IssuerKeyManagement.update_status(nil, key,"active")
      assert {:ok, updated} = IssuerKeyManagement.update_status(nil, key,"suspended")
      assert updated.status == "suspended"
    end

    test "suspended → active is valid", %{ca: ca} do
      {:ok, key} = IssuerKeyManagement.create_issuer_key(nil, ca.id, %{key_alias: "s3", algorithm: "RSA-4096"})
      {:ok, key} = IssuerKeyManagement.update_status(nil, key,"active")
      {:ok, key} = IssuerKeyManagement.update_status(nil, key,"suspended")
      assert {:ok, updated} = IssuerKeyManagement.update_status(nil, key,"active")
      assert updated.status == "active"
    end

    test "any → archived is valid", %{ca: ca} do
      {:ok, pending_key} =
        IssuerKeyManagement.create_issuer_key(nil, ca.id, %{key_alias: "s4a", algorithm: "RSA-4096"})

      assert {:ok, archived} = IssuerKeyManagement.update_status(nil, pending_key,"archived")
      assert archived.status == "archived"

      {:ok, active_key} =
        IssuerKeyManagement.create_issuer_key(nil, ca.id, %{key_alias: "s4b", algorithm: "RSA-4096"})

      {:ok, active_key} = IssuerKeyManagement.update_status(nil, active_key,"active")
      assert {:ok, archived} = IssuerKeyManagement.update_status(nil, active_key,"archived")
      assert archived.status == "archived"

      {:ok, suspended_key} =
        IssuerKeyManagement.create_issuer_key(nil, ca.id, %{key_alias: "s4c", algorithm: "RSA-4096"})

      {:ok, suspended_key} = IssuerKeyManagement.update_status(nil, suspended_key,"active")
      {:ok, suspended_key} = IssuerKeyManagement.update_status(nil, suspended_key,"suspended")
      assert {:ok, archived} = IssuerKeyManagement.update_status(nil, suspended_key,"archived")
      assert archived.status == "archived"
    end

    test "archived → archived is a noop", %{ca: ca} do
      {:ok, key} = IssuerKeyManagement.create_issuer_key(nil, ca.id, %{key_alias: "s5", algorithm: "RSA-4096"})
      {:ok, key} = IssuerKeyManagement.update_status(nil, key,"archived")
      assert {:ok, same} = IssuerKeyManagement.update_status(nil, key,"archived")
      assert same.status == "archived"
    end

    test "pending → suspended is invalid", %{ca: ca} do
      {:ok, key} = IssuerKeyManagement.create_issuer_key(nil, ca.id, %{key_alias: "s6", algorithm: "RSA-4096"})

      assert {:error, {:invalid_transition, "pending", "suspended"}} =
               IssuerKeyManagement.update_status(nil, key,"suspended")
    end

    test "archived → active is invalid", %{ca: ca} do
      {:ok, key} = IssuerKeyManagement.create_issuer_key(nil, ca.id, %{key_alias: "s7", algorithm: "RSA-4096"})
      {:ok, key} = IssuerKeyManagement.update_status(nil, key,"archived")

      assert {:error, {:invalid_transition, "archived", "active"}} =
               IssuerKeyManagement.update_status(nil, key,"active")
    end

    test "archived → suspended is invalid", %{ca: ca} do
      {:ok, key} = IssuerKeyManagement.create_issuer_key(nil, ca.id, %{key_alias: "s8", algorithm: "RSA-4096"})
      {:ok, key} = IssuerKeyManagement.update_status(nil, key,"archived")

      assert {:error, {:invalid_transition, "archived", "suspended"}} =
               IssuerKeyManagement.update_status(nil, key,"suspended")
    end

    test "pending → active does not require certificate", %{ca: ca} do
      {:ok, key} = IssuerKeyManagement.create_issuer_key(nil, ca.id, %{key_alias: "s9", algorithm: "RSA-4096"})
      assert {:ok, updated} = IssuerKeyManagement.update_status(nil, key,"active")
      assert is_nil(updated.certificate_der)
      assert is_nil(updated.certificate_pem)
    end
  end

  # ── activate_by_certificate/2 ───────────────────────────────────

  describe "activate_by_certificate/2" do
    test "sets certificate fields and activates a pending key", %{ca: ca} do
      {:ok, key} = IssuerKeyManagement.create_issuer_key(nil, ca.id, %{key_alias: "ac1", algorithm: "RSA-4096"})

      cert_attrs = %{
        certificate_der: <<0x30, 0x82, 0x01, 0x22>>,
        certificate_pem: "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"
      }

      assert {:ok, %IssuerKey{} = activated} =
               IssuerKeyManagement.activate_by_certificate(nil, key,cert_attrs)

      assert activated.status == "active"
      assert activated.certificate_der == <<0x30, 0x82, 0x01, 0x22>>
      assert activated.certificate_pem == "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"
    end

    test "rejects activation if key is not pending", %{ca: ca} do
      {:ok, key} = IssuerKeyManagement.create_issuer_key(nil, ca.id, %{key_alias: "ac2", algorithm: "RSA-4096"})
      {:ok, key} = IssuerKeyManagement.update_status(nil, key,"active")

      cert_attrs = %{
        certificate_der: <<0x30>>,
        certificate_pem: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
      }

      assert {:error, {:invalid_status, "active"}} =
               IssuerKeyManagement.activate_by_certificate(nil, key,cert_attrs)
    end

    test "rejects activation if key is archived", %{ca: ca} do
      {:ok, key} = IssuerKeyManagement.create_issuer_key(nil, ca.id, %{key_alias: "ac3", algorithm: "RSA-4096"})
      {:ok, key} = IssuerKeyManagement.update_status(nil, key,"archived")

      cert_attrs = %{
        certificate_der: <<0x30>>,
        certificate_pem: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
      }

      assert {:error, {:invalid_status, "archived"}} =
               IssuerKeyManagement.activate_by_certificate(nil, key,cert_attrs)
    end

    test "rejects activation if key is suspended", %{ca: ca} do
      {:ok, key} = IssuerKeyManagement.create_issuer_key(nil, ca.id, %{key_alias: "susp-act", algorithm: "RSA-4096"})
      {:ok, active} = IssuerKeyManagement.update_status(nil, key,"active")
      {:ok, suspended} = IssuerKeyManagement.update_status(nil, active,"suspended")

      assert {:error, {:invalid_status, "suspended"}} =
               IssuerKeyManagement.activate_by_certificate(nil, suspended,%{certificate_der: "cert", certificate_pem: "pem"})
    end
  end

  # ── set_certificate/2 ───────────────────────────────────────────

  describe "set_certificate/2" do
    test "stores certificate without changing status", %{ca: ca} do
      {:ok, key} = IssuerKeyManagement.create_issuer_key(nil, ca.id, %{key_alias: "sc1", algorithm: "RSA-4096"})

      cert_attrs = %{
        certificate_der: <<0x30, 0x82>>,
        certificate_pem: "-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----"
      }

      assert {:ok, %IssuerKey{} = updated} = IssuerKeyManagement.set_certificate(nil, key,cert_attrs)
      assert updated.status == "pending"
      assert updated.certificate_der == <<0x30, 0x82>>
      assert updated.certificate_pem == "-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----"
    end

    test "stores certificate on an active key without changing status", %{ca: ca} do
      {:ok, key} = IssuerKeyManagement.create_issuer_key(nil, ca.id, %{key_alias: "sc2", algorithm: "RSA-4096"})
      {:ok, key} = IssuerKeyManagement.update_status(nil, key,"active")

      cert_attrs = %{
        certificate_der: <<0x30, 0x82>>,
        certificate_pem: "-----BEGIN CERTIFICATE-----\nDEF\n-----END CERTIFICATE-----"
      }

      assert {:ok, %IssuerKey{} = updated} = IssuerKeyManagement.set_certificate(nil, key,cert_attrs)
      assert updated.status == "active"
      assert updated.certificate_pem == "-----BEGIN CERTIFICATE-----\nDEF\n-----END CERTIFICATE-----"
    end
  end

  # ── Helper ─────────────────────────────────────────────────────

  defp errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Regex.replace(~r"%{(\w+)}", message, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
