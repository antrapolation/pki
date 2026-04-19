defmodule PkiMnesia.Structs.RaInstance do
  @moduledoc "RA instance record."

  @fields [:id, :name, :status, :metadata, :inserted_at, :updated_at]
  def fields, do: @fields

  defstruct @fields

  @type t :: %__MODULE__{
    id: binary(),
    name: String.t(),
    status: String.t(),
    metadata: map(),
    inserted_at: DateTime.t(),
    updated_at: DateTime.t()
  }

  def new(attrs \\ %{}) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    %__MODULE__{
      id: attrs[:id] || PkiMnesia.Id.generate(),
      name: attrs[:name],
      status: Map.get(attrs, :status, "active"),
      metadata: Map.get(attrs, :metadata, %{}),
      inserted_at: attrs[:inserted_at] || now,
      updated_at: attrs[:updated_at] || now
    }
  end
end
