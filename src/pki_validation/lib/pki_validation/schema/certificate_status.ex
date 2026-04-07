defmodule PkiValidation.Schema.CertificateStatus do
  @moduledoc """
  Schema representing the status of an issued certificate.

  This table is synced from the CA database and serves as the
  read-only data source for OCSP and CRL responses.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @valid_statuses ~w(active revoked)
  @valid_revocation_reasons ~w(
    unspecified key_compromise ca_compromise affiliation_changed
    superseded cessation_of_operation certificate_hold
    remove_from_crl privilege_withdrawn aa_compromise
  )

  @primary_key {:id, :binary_id, autogenerate: false}

  schema "certificate_status" do
    field :serial_number, :string
    field :issuer_key_id, :binary_id
    field :subject_dn, :string
    field :status, :string, default: "active"
    field :not_before, :utc_datetime_usec
    field :not_after, :utc_datetime_usec
    field :revoked_at, :utc_datetime_usec
    field :revocation_reason, :string
    field :issuer_name_hash, :binary

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(serial_number issuer_key_id subject_dn status not_before not_after)a
  @optional_fields ~w(revoked_at revocation_reason issuer_name_hash)a

  @doc """
  Changeset for creating or updating a certificate status record.
  """
  def changeset(certificate_status, attrs) do
    certificate_status
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> maybe_generate_id()
    |> validate_required(@required_fields)
    |> validate_inclusion(:status, @valid_statuses)
    |> validate_inclusion(:revocation_reason, @valid_revocation_reasons)
    |> validate_revocation_fields()
    |> unique_constraint(:serial_number)
  end

  defp maybe_generate_id(changeset) do
    case get_field(changeset, :id) do
      nil -> put_change(changeset, :id, Uniq.UUID.uuid7())
      _ -> changeset
    end
  end

  defp validate_revocation_fields(changeset) do
    status = get_field(changeset, :status)
    revoked_at = get_field(changeset, :revoked_at)

    case {status, revoked_at} do
      {"revoked", nil} ->
        add_error(changeset, :revoked_at, "must be set when status is revoked")

      {"active", %DateTime{}} ->
        add_error(changeset, :revoked_at, "must not be set when status is active")

      _ ->
        changeset
    end
  end
end
