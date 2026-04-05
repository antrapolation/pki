defmodule PkiRaEngine.Schema.CertProfile do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  @statuses ["active", "archived"]

  schema "cert_profiles" do
    field :name, :string
    field :status, :string, default: "active"
    field :subject_dn_policy, :map, default: %{}
    field :issuer_policy, :map, default: %{}
    field :key_usage, :string
    field :ext_key_usage, :string
    field :digest_algo, :string
    field :validity_policy, :map, default: %{}
    field :timestamping_policy, :map, default: %{}
    field :crl_policy, :map, default: %{}
    field :ocsp_policy, :map, default: %{}
    field :ca_repository_url, :string
    field :issuer_url, :string
    field :included_extensions, :map, default: %{}
    field :renewal_policy, :map, default: %{}
    field :notification_profile, :map, default: %{}
    field :cert_publish_policy, :map, default: %{}

    has_many :csr_requests, PkiRaEngine.Schema.CsrRequest

    belongs_to :ra_instance, PkiRaEngine.Schema.RaInstance
    field :issuer_key_id, :string

    timestamps()
  end

  @required_fields [:name]
  @optional_fields [
    :status,
    :subject_dn_policy,
    :issuer_policy,
    :key_usage,
    :ext_key_usage,
    :digest_algo,
    :validity_policy,
    :timestamping_policy,
    :crl_policy,
    :ocsp_policy,
    :ca_repository_url,
    :issuer_url,
    :included_extensions,
    :renewal_policy,
    :notification_profile,
    :cert_publish_policy,
    :ra_instance_id,
    :issuer_key_id
  ]

  def changeset(cert_profile, attrs) do
    cert_profile
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_length(:name, max: 100)
    |> validate_inclusion(:status, @statuses)
    |> unique_constraint(:name)
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
