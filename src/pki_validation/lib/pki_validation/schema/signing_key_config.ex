defmodule PkiValidation.Schema.SigningKeyConfig do
  @moduledoc """
  Delegated OCSP/CRL signing key configuration per issuer key.

  Each issuer can have at most one `active` signing key at a time. The
  private key is stored encrypted at rest using AES-256-GCM with a
  password-derived key.
  """

  use Ecto.Schema
  import Ecto.Changeset

  # Single source of truth: the set of algorithm strings we accept is
  # exactly the set of algorithm strings for which a concrete Signer
  # module is registered. Looking up Registry.algorithms/0 at runtime
  # (rather than via a module attribute) avoids compile-order issues —
  # SigningKeyConfig may be compiled before Registry in the same pass —
  # while still ensuring the schema and dispatch table cannot drift apart.
  @valid_statuses ~w(active pending_rotation expired)

  @primary_key {:id, :binary_id, autogenerate: false}

  schema "signing_key_config" do
    field :issuer_key_id, :binary_id
    field :algorithm, :string
    field :certificate_pem, :string
    field :encrypted_private_key, :binary
    field :not_before, :utc_datetime_usec
    field :not_after, :utc_datetime_usec
    field :status, :string, default: "active"

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(issuer_key_id algorithm certificate_pem encrypted_private_key not_before not_after status)a

  def changeset(record, attrs) do
    record
    |> cast(attrs, @required_fields)
    |> maybe_generate_id()
    |> validate_required(@required_fields)
    |> validate_inclusion(:algorithm, PkiValidation.Crypto.Signer.Registry.algorithms())
    |> validate_inclusion(:status, @valid_statuses)
    |> unique_constraint(:issuer_key_id,
      name: :signing_key_config_one_active_per_issuer,
      message: "only one active signing key per issuer"
    )
  end

  defp maybe_generate_id(changeset) do
    case get_field(changeset, :id) do
      nil -> put_change(changeset, :id, Uniq.UUID.uuid7())
      _ -> changeset
    end
  end
end
