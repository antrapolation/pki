defmodule PkiCaEngine.Schema.IssuerKey do
  use Ecto.Schema
  import Ecto.Changeset

  @statuses ["pending", "active", "suspended", "archived"]

  schema "issuer_keys" do
    field :key_alias, :string
    field :algorithm, :string
    field :status, :string, default: "pending"
    field :keystore_ref, :binary
    field :is_root, :boolean, default: false
    field :threshold_config, :map, default: %{}
    field :certificate_der, :binary
    field :certificate_pem, :string

    belongs_to :ca_instance, PkiCaEngine.Schema.CaInstance

    has_many :keypair_accesses, PkiCaEngine.Schema.KeypairAccess
    has_many :threshold_shares, PkiCaEngine.Schema.ThresholdShare
    has_many :key_ceremonies, PkiCaEngine.Schema.KeyCeremony
    has_many :issued_certificates, PkiCaEngine.Schema.IssuedCertificate

    timestamps()
  end

  def changeset(key, attrs) do
    key
    |> cast(attrs, [
      :ca_instance_id, :key_alias, :algorithm, :status, :keystore_ref,
      :is_root, :threshold_config, :certificate_der, :certificate_pem
    ])
    |> validate_required([:ca_instance_id, :key_alias, :algorithm])
    |> validate_inclusion(:status, @statuses)
    |> foreign_key_constraint(:ca_instance_id)
    |> unique_constraint([:ca_instance_id, :key_alias])
  end

  @doc """
  Changeset that only updates the status field.
  """
  def update_status_changeset(key, attrs) do
    key
    |> cast(attrs, [:status])
    |> validate_required([:status])
    |> validate_inclusion(:status, @statuses)
  end

  @doc """
  Sets certificate_der, certificate_pem, and status to "active".
  Used when activating a pending key by uploading a certificate.
  """
  def activate_changeset(key, attrs) do
    key
    |> cast(attrs, [:certificate_der, :certificate_pem])
    |> put_change(:status, "active")
    |> validate_required([:certificate_der, :certificate_pem])
  end

  @doc """
  Sets certificate_der and certificate_pem without changing status.
  """
  def certificate_changeset(key, attrs) do
    key
    |> cast(attrs, [:certificate_der, :certificate_pem])
  end
end
