defmodule PkiCaEngine.SchemaTest do
  use PkiCaEngine.DataCase, async: true

  alias PkiCaEngine.Schema.{
    CaInstance,
    CaUser,
    Keystore,
    IssuerKey,
    KeypairAccess,
    ThresholdShare,
    KeyCeremony,
    IssuedCertificate
  }

  # -- CaInstance --

  describe "CaInstance" do
    @valid_attrs %{name: "test-ca", status: "active", created_by: "admin"}

    test "valid changeset" do
      changeset = CaInstance.changeset(%CaInstance{}, @valid_attrs)
      assert changeset.valid?
    end

    test "invalid changeset - missing required fields" do
      changeset = CaInstance.changeset(%CaInstance{}, %{})
      refute changeset.valid?
      assert %{name: ["can't be blank"]} = errors_on(changeset)
    end

    test "invalid status rejected" do
      changeset = CaInstance.changeset(%CaInstance{}, %{@valid_attrs | status: "bogus"})
      refute changeset.valid?
      assert %{status: [_]} = errors_on(changeset)
    end

    test "unique name constraint" do
      {:ok, _} = Repo.insert(CaInstance.changeset(%CaInstance{}, @valid_attrs))

      {:error, changeset} =
        Repo.insert(CaInstance.changeset(%CaInstance{}, @valid_attrs))

      assert %{name: ["has already been taken"]} = errors_on(changeset)
    end

    test "generates UUIDv7 id" do
      changeset = CaInstance.changeset(%CaInstance{}, @valid_attrs)
      assert is_binary(Ecto.Changeset.get_field(changeset, :id))
    end
  end

  # -- CaUser --

  describe "CaUser" do
    setup do
      {:ok, ca} = Repo.insert(CaInstance.changeset(%CaInstance{}, %{name: "user-ca", created_by: "admin"}))
      %{ca: ca}
    end

    test "valid changeset", %{ca: ca} do
      attrs = %{ca_instance_id: ca.id, display_name: "Alice", role: "ca_admin"}
      changeset = CaUser.changeset(%CaUser{}, attrs)
      assert changeset.valid?
    end

    test "invalid changeset - missing required fields" do
      changeset = CaUser.changeset(%CaUser{}, %{})
      refute changeset.valid?
      errors = errors_on(changeset)
      assert %{role: ["can't be blank"], ca_instance_id: ["can't be blank"]} = errors
    end

    test "invalid role rejected", %{ca: ca} do
      attrs = %{ca_instance_id: ca.id, role: "superadmin"}
      changeset = CaUser.changeset(%CaUser{}, attrs)
      refute changeset.valid?
      assert %{role: [_]} = errors_on(changeset)
    end

    test "invalid status rejected", %{ca: ca} do
      attrs = %{ca_instance_id: ca.id, role: "ca_admin", status: "deleted"}
      changeset = CaUser.changeset(%CaUser{}, attrs)
      refute changeset.valid?
      assert %{status: [_]} = errors_on(changeset)
    end

    test "generates UUIDv7 id", %{ca: ca} do
      attrs = %{ca_instance_id: ca.id, role: "ca_admin"}
      changeset = CaUser.changeset(%CaUser{}, attrs)
      assert is_binary(Ecto.Changeset.get_field(changeset, :id))
    end
  end

  # -- Keystore --

  describe "Keystore" do
    setup do
      {:ok, ca} = Repo.insert(CaInstance.changeset(%CaInstance{}, %{name: "ks-ca", created_by: "admin"}))
      %{ca: ca}
    end

    test "valid changeset", %{ca: ca} do
      attrs = %{ca_instance_id: ca.id, type: "software", provider_name: "soft"}
      changeset = Keystore.changeset(%Keystore{}, attrs)
      assert changeset.valid?
    end

    test "invalid changeset - missing required fields" do
      changeset = Keystore.changeset(%Keystore{}, %{})
      refute changeset.valid?
      errors = errors_on(changeset)
      assert %{ca_instance_id: ["can't be blank"], type: ["can't be blank"]} = errors
    end

    test "invalid type rejected", %{ca: ca} do
      attrs = %{ca_instance_id: ca.id, type: "cloud"}
      changeset = Keystore.changeset(%Keystore{}, attrs)
      refute changeset.valid?
      assert %{type: [_]} = errors_on(changeset)
    end

    test "invalid status rejected", %{ca: ca} do
      attrs = %{ca_instance_id: ca.id, type: "software", status: "deleted"}
      changeset = Keystore.changeset(%Keystore{}, attrs)
      refute changeset.valid?
      assert %{status: [_]} = errors_on(changeset)
    end
  end

  # -- IssuerKey --

  describe "IssuerKey" do
    setup do
      {:ok, ca} = Repo.insert(CaInstance.changeset(%CaInstance{}, %{name: "ik-ca", created_by: "admin"}))
      %{ca: ca}
    end

    test "valid changeset", %{ca: ca} do
      attrs = %{ca_instance_id: ca.id, key_alias: "root-key-1", algorithm: "ML-DSA-65"}
      changeset = IssuerKey.changeset(%IssuerKey{}, attrs)
      assert changeset.valid?
    end

    test "invalid changeset - missing required fields" do
      changeset = IssuerKey.changeset(%IssuerKey{}, %{})
      refute changeset.valid?
      errors = errors_on(changeset)
      assert %{ca_instance_id: ["can't be blank"], key_alias: ["can't be blank"], algorithm: ["can't be blank"]} = errors
    end

    test "invalid status rejected", %{ca: ca} do
      attrs = %{ca_instance_id: ca.id, key_alias: "k1", algorithm: "ML-DSA-65", status: "deleted"}
      changeset = IssuerKey.changeset(%IssuerKey{}, attrs)
      refute changeset.valid?
      assert %{status: [_]} = errors_on(changeset)
    end

    test "unique ca_instance_id + key_alias constraint", %{ca: ca} do
      attrs = %{ca_instance_id: ca.id, key_alias: "root-key", algorithm: "ML-DSA-65"}
      {:ok, _} = Repo.insert(IssuerKey.changeset(%IssuerKey{}, attrs))
      {:error, changeset} = Repo.insert(IssuerKey.changeset(%IssuerKey{}, attrs))
      assert %{ca_instance_id: ["has already been taken"]} = errors_on(changeset)
    end
  end

  # -- KeypairAccess --

  describe "KeypairAccess" do
    setup do
      {:ok, ca} = Repo.insert(CaInstance.changeset(%CaInstance{}, %{name: "kpa-ca", created_by: "admin"}))
      {:ok, user} = Repo.insert(CaUser.changeset(%CaUser{}, %{ca_instance_id: ca.id, role: "key_manager"}))
      {:ok, granter} = Repo.insert(CaUser.changeset(%CaUser{}, %{ca_instance_id: ca.id, role: "ca_admin"}))
      {:ok, key} = Repo.insert(IssuerKey.changeset(%IssuerKey{}, %{ca_instance_id: ca.id, key_alias: "kpa-key", algorithm: "ML-DSA-65"}))
      %{key: key, user: user, granter: granter}
    end

    test "valid changeset", %{key: key, user: user, granter: granter} do
      attrs = %{issuer_key_id: key.id, user_id: user.id, granted_by: granter.id, granted_at: DateTime.utc_now()}
      changeset = KeypairAccess.changeset(%KeypairAccess{}, attrs)
      assert changeset.valid?
    end

    test "invalid changeset - missing required fields" do
      changeset = KeypairAccess.changeset(%KeypairAccess{}, %{})
      refute changeset.valid?
      errors = errors_on(changeset)
      assert %{issuer_key_id: ["can't be blank"], user_id: ["can't be blank"], granted_at: ["can't be blank"]} = errors
    end

    test "unique issuer_key_id + user_id constraint", %{key: key, user: user, granter: granter} do
      attrs = %{issuer_key_id: key.id, user_id: user.id, granted_by: granter.id, granted_at: DateTime.utc_now()}
      {:ok, _} = Repo.insert(KeypairAccess.changeset(%KeypairAccess{}, attrs))
      {:error, changeset} = Repo.insert(KeypairAccess.changeset(%KeypairAccess{}, attrs))
      assert %{issuer_key_id: ["has already been taken"]} = errors_on(changeset)
    end
  end

  # -- ThresholdShare --

  describe "ThresholdShare" do
    setup do
      {:ok, ca} = Repo.insert(CaInstance.changeset(%CaInstance{}, %{name: "ts-ca", created_by: "admin"}))
      {:ok, user} = Repo.insert(CaUser.changeset(%CaUser{}, %{ca_instance_id: ca.id, role: "key_manager"}))
      {:ok, key} = Repo.insert(IssuerKey.changeset(%IssuerKey{}, %{ca_instance_id: ca.id, key_alias: "ts-key", algorithm: "ML-DSA-65"}))
      %{key: key, user: user}
    end

    test "valid changeset", %{key: key, user: user} do
      attrs = %{
        issuer_key_id: key.id,
        custodian_user_id: user.id,
        share_index: 1,
        encrypted_share: <<1, 2, 3>>,
        min_shares: 2,
        total_shares: 3
      }
      changeset = ThresholdShare.changeset(%ThresholdShare{}, attrs)
      assert changeset.valid?
    end

    test "invalid changeset - missing required fields" do
      changeset = ThresholdShare.changeset(%ThresholdShare{}, %{})
      refute changeset.valid?
      errors = errors_on(changeset)
      assert %{issuer_key_id: ["can't be blank"], custodian_user_id: ["can't be blank"]} = errors
    end

    test "unique issuer_key_id + custodian_user_id constraint", %{key: key, user: user} do
      attrs = %{
        issuer_key_id: key.id,
        custodian_user_id: user.id,
        share_index: 1,
        encrypted_share: <<1, 2, 3>>,
        min_shares: 2,
        total_shares: 3
      }
      {:ok, _} = Repo.insert(ThresholdShare.changeset(%ThresholdShare{}, attrs))
      {:error, changeset} = Repo.insert(ThresholdShare.changeset(%ThresholdShare{}, attrs))
      assert %{issuer_key_id: ["has already been taken"]} = errors_on(changeset)
    end
  end

  # -- KeyCeremony --

  describe "KeyCeremony" do
    setup do
      {:ok, ca} = Repo.insert(CaInstance.changeset(%CaInstance{}, %{name: "kc-ca", created_by: "admin"}))
      {:ok, user} = Repo.insert(CaUser.changeset(%CaUser{}, %{ca_instance_id: ca.id, role: "ca_admin"}))
      {:ok, ks} = Repo.insert(Keystore.changeset(%Keystore{}, %{ca_instance_id: ca.id, type: "software"}))
      %{ca: ca, user: user, keystore: ks}
    end

    test "valid changeset", %{ca: ca, user: user, keystore: ks} do
      attrs = %{
        ca_instance_id: ca.id,
        ceremony_type: "sync",
        initiated_by: user.id,
        algorithm: "ML-DSA-65",
        keystore_id: ks.id,
        threshold_k: 2,
        threshold_n: 3
      }
      changeset = KeyCeremony.changeset(%KeyCeremony{}, attrs)
      assert changeset.valid?
    end

    test "invalid changeset - missing required fields" do
      changeset = KeyCeremony.changeset(%KeyCeremony{}, %{})
      refute changeset.valid?
      errors = errors_on(changeset)
      assert %{ca_instance_id: ["can't be blank"], ceremony_type: ["can't be blank"]} = errors
    end

    test "invalid ceremony_type rejected", %{ca: ca} do
      attrs = %{ca_instance_id: ca.id, ceremony_type: "manual"}
      changeset = KeyCeremony.changeset(%KeyCeremony{}, attrs)
      refute changeset.valid?
      assert %{ceremony_type: [_]} = errors_on(changeset)
    end

    test "invalid status rejected", %{ca: ca} do
      attrs = %{ca_instance_id: ca.id, ceremony_type: "sync", status: "cancelled"}
      changeset = KeyCeremony.changeset(%KeyCeremony{}, attrs)
      refute changeset.valid?
      assert %{status: [_]} = errors_on(changeset)
    end
  end

  # -- IssuedCertificate --

  describe "IssuedCertificate" do
    setup do
      {:ok, ca} = Repo.insert(CaInstance.changeset(%CaInstance{}, %{name: "ic-ca", created_by: "admin"}))
      {:ok, key} = Repo.insert(IssuerKey.changeset(%IssuerKey{}, %{ca_instance_id: ca.id, key_alias: "ic-key", algorithm: "ML-DSA-65"}))
      %{key: key}
    end

    test "valid changeset", %{key: key} do
      attrs = %{
        serial_number: "AABBCCDD01",
        issuer_key_id: key.id,
        subject_dn: "CN=test",
        not_before: ~U[2026-01-01 00:00:00Z],
        not_after: ~U[2027-01-01 00:00:00Z]
      }
      changeset = IssuedCertificate.changeset(%IssuedCertificate{}, attrs)
      assert changeset.valid?
    end

    test "invalid changeset - missing required fields" do
      changeset = IssuedCertificate.changeset(%IssuedCertificate{}, %{})
      refute changeset.valid?
      errors = errors_on(changeset)
      assert %{serial_number: ["can't be blank"], issuer_key_id: ["can't be blank"], subject_dn: ["can't be blank"]} = errors
    end

    test "invalid status rejected", %{key: key} do
      attrs = %{
        serial_number: "AA01",
        issuer_key_id: key.id,
        subject_dn: "CN=test",
        not_before: ~U[2026-01-01 00:00:00Z],
        not_after: ~U[2027-01-01 00:00:00Z],
        status: "expired"
      }
      changeset = IssuedCertificate.changeset(%IssuedCertificate{}, attrs)
      refute changeset.valid?
      assert %{status: [_]} = errors_on(changeset)
    end

    test "unique serial_number constraint", %{key: key} do
      attrs = %{
        serial_number: "UNIQUE01",
        issuer_key_id: key.id,
        subject_dn: "CN=test",
        not_before: ~U[2026-01-01 00:00:00Z],
        not_after: ~U[2027-01-01 00:00:00Z]
      }
      {:ok, _} = Repo.insert(IssuedCertificate.changeset(%IssuedCertificate{}, attrs))
      {:error, changeset} = Repo.insert(IssuedCertificate.changeset(%IssuedCertificate{}, attrs))
      assert %{serial_number: ["has already been taken"]} = errors_on(changeset)
    end
  end

  # -- Helper --

  defp errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Regex.replace(~r"%{(\w+)}", message, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
