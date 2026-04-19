defmodule PkiMnesia.Structs.ApiKey do
  @moduledoc "External API access key with hash-based lookup."

  @fields [:id, :ra_instance_id, :name, :key_hash, :key_prefix, :permissions,
           :status, :last_used_at, :expires_at, :inserted_at, :updated_at]
  def fields, do: @fields

  defstruct @fields

  @type t :: %__MODULE__{
    id: binary(),
    ra_instance_id: binary(),
    name: String.t(),
    key_hash: binary(),
    key_prefix: String.t(),
    permissions: [String.t()],
    status: String.t(),
    last_used_at: DateTime.t() | nil,
    expires_at: DateTime.t() | nil,
    inserted_at: DateTime.t(),
    updated_at: DateTime.t()
  }

  def new(attrs \\ %{}) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    %__MODULE__{
      id: attrs[:id] || PkiMnesia.Id.generate(),
      ra_instance_id: attrs[:ra_instance_id],
      name: attrs[:name],
      key_hash: attrs[:key_hash],
      key_prefix: attrs[:key_prefix],
      permissions: Map.get(attrs, :permissions, ["csr:submit"]),
      status: Map.get(attrs, :status, "active"),
      last_used_at: attrs[:last_used_at],
      expires_at: attrs[:expires_at],
      inserted_at: attrs[:inserted_at] || now,
      updated_at: attrs[:updated_at] || now
    }
  end
end
