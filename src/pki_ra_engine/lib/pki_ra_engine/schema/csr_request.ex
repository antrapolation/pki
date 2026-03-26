defmodule PkiRaEngine.Schema.CsrRequest do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  @statuses ["pending", "verified", "approved", "rejected", "issued"]

  schema "csr_requests" do
    field :csr_der, :binary
    field :csr_pem, :string
    field :subject_dn, :string
    field :status, :string, default: "pending"
    field :submitted_at, :utc_datetime_usec
    field :reviewed_at, :utc_datetime_usec
    field :rejection_reason, :string
    field :issued_cert_serial, :string

    belongs_to :cert_profile, PkiRaEngine.Schema.CertProfile
    belongs_to :reviewer, PkiRaEngine.Schema.RaUser, foreign_key: :reviewed_by

    timestamps()
  end

  @required_fields [:subject_dn, :cert_profile_id, :submitted_at]
  @optional_fields [
    :csr_der,
    :csr_pem,
    :status,
    :reviewed_by,
    :reviewed_at,
    :rejection_reason,
    :issued_cert_serial
  ]

  def changeset(csr_request, attrs) do
    csr_request
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:status, @statuses)
    |> foreign_key_constraint(:cert_profile_id)
    |> foreign_key_constraint(:reviewed_by)
    |> maybe_generate_id()
  end

  def statuses, do: @statuses

  defp maybe_generate_id(changeset) do
    if get_field(changeset, :id) do
      changeset
    else
      put_change(changeset, :id, Uniq.UUID.uuid7())
    end
  end
end
