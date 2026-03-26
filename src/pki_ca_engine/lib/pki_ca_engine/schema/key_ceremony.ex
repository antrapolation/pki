defmodule PkiCaEngine.Schema.KeyCeremony do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  @ceremony_types ["sync", "async"]
  @statuses ["initiated", "in_progress", "completed", "failed"]

  schema "key_ceremonies" do
    field :ceremony_type, :string
    field :status, :string, default: "initiated"
    field :participants, :map, default: %{}
    field :algorithm, :string
    field :threshold_k, :integer
    field :threshold_n, :integer
    field :domain_info, :map, default: %{}
    field :window_expires_at, :utc_datetime

    belongs_to :ca_instance, PkiCaEngine.Schema.CaInstance
    belongs_to :issuer_key, PkiCaEngine.Schema.IssuerKey
    belongs_to :initiator, PkiCaEngine.Schema.CaUser, foreign_key: :initiated_by
    belongs_to :keystore, PkiCaEngine.Schema.Keystore

    timestamps()
  end

  def changeset(ceremony, attrs) do
    ceremony
    |> cast(attrs, [
      :ca_instance_id, :issuer_key_id, :ceremony_type, :status, :initiated_by,
      :participants, :algorithm, :keystore_id, :threshold_k, :threshold_n,
      :domain_info, :window_expires_at
    ])
    |> validate_required([:ca_instance_id, :ceremony_type])
    |> validate_inclusion(:ceremony_type, @ceremony_types)
    |> validate_inclusion(:status, @statuses)
    |> foreign_key_constraint(:ca_instance_id)
    |> foreign_key_constraint(:issuer_key_id)
    |> foreign_key_constraint(:initiated_by)
    |> foreign_key_constraint(:keystore_id)
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
