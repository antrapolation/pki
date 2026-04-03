defmodule PkiCaEngine.Schema.CeremonyAttestation do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  @phases ["preparation", "key_generation", "completion"]

  schema "ceremony_attestations" do
    field :auditor_user_id, :binary_id
    field :phase, :string
    field :attested_at, :utc_datetime
    field :details, :map, default: %{}

    belongs_to :ceremony, PkiCaEngine.Schema.KeyCeremony

    timestamps()
  end

  def changeset(attestation, attrs) do
    attestation
    |> cast(attrs, [:ceremony_id, :auditor_user_id, :phase, :attested_at, :details])
    |> validate_required([:ceremony_id, :auditor_user_id, :phase, :attested_at])
    |> validate_inclusion(:phase, @phases)
    |> foreign_key_constraint(:ceremony_id)
    |> unique_constraint([:ceremony_id, :phase])
    |> maybe_generate_id()
  end

  defp maybe_generate_id(changeset) do
    if get_field(changeset, :id) do
      changeset
    else
      put_change(changeset, :id, Uniq.UUID.uuid7())
    end
  end
end
