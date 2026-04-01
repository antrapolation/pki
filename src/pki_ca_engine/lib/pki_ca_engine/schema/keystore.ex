defmodule PkiCaEngine.Schema.Keystore do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  @types ["software", "hsm"]
  @statuses ["active", "inactive"]

  schema "keystores" do
    field :type, :string
    field :config, :binary
    field :status, :string, default: "active"
    field :provider_name, :string

    belongs_to :ca_instance, PkiCaEngine.Schema.CaInstance

    has_many :key_ceremonies, PkiCaEngine.Schema.KeyCeremony

    timestamps()
  end

  def changeset(keystore, attrs) do
    keystore
    |> cast(attrs, [:ca_instance_id, :type, :config, :status, :provider_name])
    |> validate_required([:ca_instance_id, :type])
    |> validate_inclusion(:type, @types)
    |> validate_inclusion(:status, @statuses)
    |> validate_hsm_config()
    |> foreign_key_constraint(:ca_instance_id)
    |> maybe_generate_id()
  end

  def update_changeset(keystore, attrs) do
    keystore
    |> cast(attrs, [:config, :status, :provider_name])
    |> validate_inclusion(:status, @statuses)
  end

  @doc "Decodes the config binary field to a map. Returns nil for nil/empty."
  def decode_config(nil), do: nil
  def decode_config(bin) when is_binary(bin) do
    case Jason.decode(bin) do
      {:ok, map} -> map
      _ -> nil
    end
  end

  @doc "Encodes a config map to JSON binary for storage."
  def encode_config(nil), do: nil
  def encode_config(map) when is_map(map) do
    case Jason.encode(map) do
      {:ok, json} -> json
      {:error, _} -> nil
    end
  end

  defp validate_hsm_config(changeset) do
    if get_field(changeset, :type) == "hsm" and is_nil(get_field(changeset, :config)) do
      add_error(changeset, :config, "is required for HSM keystores")
    else
      changeset
    end
  end

  defp maybe_generate_id(changeset) do
    if get_field(changeset, :id) do
      changeset
    else
      put_change(changeset, :id, Uniq.UUID.uuid7())
    end
  end
end
