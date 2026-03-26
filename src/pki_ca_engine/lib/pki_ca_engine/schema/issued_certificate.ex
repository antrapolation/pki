defmodule PkiCaEngine.Schema.IssuedCertificate do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  @statuses ["active", "revoked"]

  schema "issued_certificates" do
    field :serial_number, :string
    field :subject_dn, :string
    field :cert_der, :binary
    field :cert_pem, :string
    field :not_before, :utc_datetime
    field :not_after, :utc_datetime
    field :status, :string, default: "active"
    field :revoked_at, :utc_datetime
    field :revocation_reason, :string
    field :cert_profile_id, :string

    belongs_to :issuer_key, PkiCaEngine.Schema.IssuerKey

    timestamps()
  end

  def changeset(cert, attrs) do
    cert
    |> cast(attrs, [
      :serial_number, :issuer_key_id, :subject_dn, :cert_der, :cert_pem,
      :not_before, :not_after, :status, :revoked_at, :revocation_reason,
      :cert_profile_id
    ])
    |> validate_required([:serial_number, :issuer_key_id, :subject_dn, :not_before, :not_after])
    |> validate_inclusion(:status, @statuses)
    |> foreign_key_constraint(:issuer_key_id)
    |> unique_constraint(:serial_number)
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
