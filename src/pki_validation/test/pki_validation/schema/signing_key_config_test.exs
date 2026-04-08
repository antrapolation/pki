defmodule PkiValidation.Schema.SigningKeyConfigTest do
  use PkiValidation.DataCase, async: true

  alias PkiValidation.Schema.SigningKeyConfig
  alias PkiValidation.Repo

  @valid_attrs %{
    issuer_key_id: Uniq.UUID.uuid7(),
    algorithm: "ecc_p256",
    certificate_pem: "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----",
    encrypted_private_key: <<1, 2, 3>>,
    not_before: DateTime.utc_now(),
    not_after: DateTime.utc_now() |> DateTime.add(30, :day),
    status: "active"
  }

  test "valid attrs produce a valid changeset" do
    changeset = SigningKeyConfig.changeset(%SigningKeyConfig{}, @valid_attrs)
    assert changeset.valid?
  end

  test "requires issuer_key_id" do
    attrs = Map.delete(@valid_attrs, :issuer_key_id)
    changeset = SigningKeyConfig.changeset(%SigningKeyConfig{}, attrs)
    refute changeset.valid?
    assert %{issuer_key_id: ["can't be blank"]} = errors_on(changeset)
  end

  test "validates algorithm inclusion" do
    attrs = Map.put(@valid_attrs, :algorithm, "bogus_alg")
    changeset = SigningKeyConfig.changeset(%SigningKeyConfig{}, attrs)
    refute changeset.valid?
  end

  test "validates status inclusion" do
    attrs = Map.put(@valid_attrs, :status, "bogus")
    changeset = SigningKeyConfig.changeset(%SigningKeyConfig{}, attrs)
    refute changeset.valid?
  end

  test "persists to database with unique constraint on issuer_key_id where status=active" do
    {:ok, _} = %SigningKeyConfig{} |> SigningKeyConfig.changeset(@valid_attrs) |> Repo.insert()

    {:error, changeset} =
      %SigningKeyConfig{} |> SigningKeyConfig.changeset(@valid_attrs) |> Repo.insert()

    assert %{issuer_key_id: ["only one active signing key per issuer"]} = errors_on(changeset)
  end

  defp errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Regex.replace(~r"%{(\w+)}", message, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
