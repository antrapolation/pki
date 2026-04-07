defmodule PkiValidation.Schema.CrlMetadata do
  @moduledoc """
  Per-issuer CRL generation metadata.

  Tracks the monotonic CRL number used in the `cRLNumber` extension and
  caches the latest signed DER bytes so we don't have to re-sign on
  every request.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}

  schema "crl_metadata" do
    field :issuer_key_id, :binary_id
    field :crl_number, :integer, default: 1
    field :last_generated_at, :utc_datetime_usec
    field :last_der_bytes, :binary
    field :last_der_size, :integer, default: 0
    field :generation_count, :integer, default: 0

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(issuer_key_id crl_number generation_count)a
  @optional_fields ~w(last_generated_at last_der_bytes last_der_size)a

  def changeset(record, attrs) do
    record
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> maybe_generate_id()
    |> validate_required(@required_fields)
    |> validate_number(:crl_number, greater_than: 0)
    |> unique_constraint(:issuer_key_id)
  end

  defp maybe_generate_id(changeset) do
    case get_field(changeset, :id) do
      nil -> put_change(changeset, :id, Uniq.UUID.uuid7())
      _ -> changeset
    end
  end
end
