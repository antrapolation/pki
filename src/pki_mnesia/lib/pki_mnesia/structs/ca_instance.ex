defmodule PkiMnesia.Structs.CaInstance do
  @moduledoc "CA instance in the CA hierarchy (root, sub-CAs)."

  defstruct [
    :id,
    :name,
    :parent_id,
    :is_root,
    :is_offline,
    :status,
    :max_depth,
    :metadata,
    :inserted_at,
    :updated_at
  ]

  @type t :: %__MODULE__{
    id: binary(),
    name: String.t(),
    parent_id: binary() | nil,
    is_root: boolean(),
    is_offline: boolean(),
    status: String.t(),
    max_depth: integer(),
    metadata: map(),
    inserted_at: DateTime.t(),
    updated_at: DateTime.t()
  }

  def new(attrs \\ %{}) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    %__MODULE__{
      id: attrs[:id] || PkiMnesia.Id.generate(),
      name: attrs[:name],
      parent_id: attrs[:parent_id],
      is_root: Map.get(attrs, :is_root, false),
      is_offline: Map.get(attrs, :is_offline, false),
      status: Map.get(attrs, :status, "active"),
      max_depth: Map.get(attrs, :max_depth, 2),
      metadata: Map.get(attrs, :metadata, %{}),
      inserted_at: attrs[:inserted_at] || now,
      updated_at: attrs[:updated_at] || now
    }
  end
end
