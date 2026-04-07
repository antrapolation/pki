defmodule PkiValidation.Schema.CrlMetadataTest do
  use PkiValidation.DataCase, async: true

  alias PkiValidation.Schema.CrlMetadata
  alias PkiValidation.Repo

  @valid_attrs %{
    issuer_key_id: Uniq.UUID.uuid7(),
    crl_number: 1,
    last_generated_at: DateTime.utc_now(),
    last_der_bytes: <<0, 1, 2>>,
    last_der_size: 3,
    generation_count: 1
  }

  test "valid attrs produce a valid changeset" do
    changeset = CrlMetadata.changeset(%CrlMetadata{}, @valid_attrs)
    assert changeset.valid?
  end

  test "requires issuer_key_id" do
    attrs = Map.delete(@valid_attrs, :issuer_key_id)
    changeset = CrlMetadata.changeset(%CrlMetadata{}, attrs)
    refute changeset.valid?
  end

  test "issuer_key_id is unique" do
    {:ok, _} = %CrlMetadata{} |> CrlMetadata.changeset(@valid_attrs) |> Repo.insert()
    {:error, changeset} = %CrlMetadata{} |> CrlMetadata.changeset(@valid_attrs) |> Repo.insert()
    refute changeset.valid?
  end

  test "crl_number must be positive" do
    attrs = Map.put(@valid_attrs, :crl_number, 0)
    changeset = CrlMetadata.changeset(%CrlMetadata{}, attrs)
    refute changeset.valid?
  end

  test "rejects nil generation_count" do
    attrs = Map.put(@valid_attrs, :generation_count, nil)
    changeset = CrlMetadata.changeset(%CrlMetadata{}, attrs)
    refute changeset.valid?
  end
end
