defmodule PkiValidation.Schema.CertificateStatusTest do
  use PkiValidation.DataCase, async: true

  alias PkiValidation.Schema.CertificateStatus

  @valid_attrs %{
    serial_number: "ABC123",
    issuer_key_id: 1,
    subject_dn: "CN=test.example.com,O=Test,C=MY",
    status: "active",
    not_before: ~U[2026-01-01 00:00:00.000000Z],
    not_after: ~U[2027-01-01 00:00:00.000000Z]
  }

  describe "changeset/2" do
    test "valid attrs produce a valid changeset" do
      changeset = CertificateStatus.changeset(%CertificateStatus{}, @valid_attrs)
      assert changeset.valid?
    end

    test "requires serial_number" do
      attrs = Map.delete(@valid_attrs, :serial_number)
      changeset = CertificateStatus.changeset(%CertificateStatus{}, attrs)
      refute changeset.valid?
      assert "can't be blank" in errors_on(changeset, :serial_number)
    end

    test "requires issuer_key_id" do
      attrs = Map.delete(@valid_attrs, :issuer_key_id)
      changeset = CertificateStatus.changeset(%CertificateStatus{}, attrs)
      refute changeset.valid?
      assert "can't be blank" in errors_on(changeset, :issuer_key_id)
    end

    test "requires subject_dn" do
      attrs = Map.delete(@valid_attrs, :subject_dn)
      changeset = CertificateStatus.changeset(%CertificateStatus{}, attrs)
      refute changeset.valid?
      assert "can't be blank" in errors_on(changeset, :subject_dn)
    end

    test "validates status inclusion" do
      attrs = Map.put(@valid_attrs, :status, "invalid")
      changeset = CertificateStatus.changeset(%CertificateStatus{}, attrs)
      refute changeset.valid?
      assert "is invalid" in errors_on(changeset, :status)
    end

    test "revoked status requires revoked_at" do
      attrs = Map.put(@valid_attrs, :status, "revoked")
      changeset = CertificateStatus.changeset(%CertificateStatus{}, attrs)
      refute changeset.valid?
      assert "must be set when status is revoked" in errors_on(changeset, :revoked_at)
    end

    test "revoked status with revoked_at is valid" do
      attrs =
        @valid_attrs
        |> Map.put(:status, "revoked")
        |> Map.put(:revoked_at, ~U[2026-06-01 00:00:00.000000Z])
        |> Map.put(:revocation_reason, "key_compromise")

      changeset = CertificateStatus.changeset(%CertificateStatus{}, attrs)
      assert changeset.valid?
    end

    test "active status rejects revoked_at" do
      attrs = Map.put(@valid_attrs, :revoked_at, ~U[2026-06-01 00:00:00.000000Z])
      changeset = CertificateStatus.changeset(%CertificateStatus{}, attrs)
      refute changeset.valid?
      assert "must not be set when status is active" in errors_on(changeset, :revoked_at)
    end

    test "validates revocation_reason inclusion" do
      attrs =
        @valid_attrs
        |> Map.put(:status, "revoked")
        |> Map.put(:revoked_at, ~U[2026-06-01 00:00:00.000000Z])
        |> Map.put(:revocation_reason, "invalid_reason")

      changeset = CertificateStatus.changeset(%CertificateStatus{}, attrs)
      refute changeset.valid?
      assert "is invalid" in errors_on(changeset, :revocation_reason)
    end

    test "persists to database" do
      changeset = CertificateStatus.changeset(%CertificateStatus{}, @valid_attrs)
      assert {:ok, cert} = Repo.insert(changeset)
      assert cert.serial_number == "ABC123"
      assert cert.status == "active"
    end

    test "enforces unique serial_number" do
      changeset = CertificateStatus.changeset(%CertificateStatus{}, @valid_attrs)
      assert {:ok, _} = Repo.insert(changeset)

      duplicate = CertificateStatus.changeset(%CertificateStatus{}, @valid_attrs)
      assert {:error, changeset} = Repo.insert(duplicate)
      assert "has already been taken" in errors_on(changeset, :serial_number)
    end
  end

  defp errors_on(changeset, field) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
    |> Map.get(field, [])
  end
end
