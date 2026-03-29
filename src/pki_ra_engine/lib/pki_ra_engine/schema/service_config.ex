defmodule PkiRaEngine.Schema.ServiceConfig do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  @service_types ["csr_web", "crl", "ldap", "ocsp", "OCSP Responder", "CRL Distribution", "TSA"]

  schema "service_configs" do
    field :service_type, :string
    field :port, :integer
    field :url, :string
    field :rate_limit, :integer
    field :ip_whitelist, :map, default: %{}
    field :ip_blacklist, :map, default: %{}
    field :connection_security, :string
    field :credentials, :binary
    field :ca_engine_ref, :string

    timestamps()
  end

  @required_fields [:service_type]
  @optional_fields [
    :port,
    :url,
    :rate_limit,
    :ip_whitelist,
    :ip_blacklist,
    :connection_security,
    :credentials,
    :ca_engine_ref
  ]

  def changeset(service_config, attrs) do
    service_config
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:service_type, @service_types)
    |> unique_constraint(:service_type)
    |> maybe_generate_id()
  end

  def service_types, do: @service_types

  defp maybe_generate_id(changeset) do
    if get_field(changeset, :id) do
      changeset
    else
      put_change(changeset, :id, Uniq.UUID.uuid7())
    end
  end
end
