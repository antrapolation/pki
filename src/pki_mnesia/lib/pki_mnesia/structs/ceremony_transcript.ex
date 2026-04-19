defmodule PkiMnesia.Structs.CeremonyTranscript do
  @moduledoc """
  Serialized event log for ceremony PDF generation.
  Entries are a list of maps: %{timestamp, actor, action, details}.
  """

  @fields [:id, :ceremony_id, :entries, :finalized_at, :inserted_at]
  def fields, do: @fields

  defstruct @fields

  @type t :: %__MODULE__{
    id: binary(),
    ceremony_id: binary(),
    entries: [map()],
    finalized_at: DateTime.t() | nil,
    inserted_at: DateTime.t()
  }

  def new(attrs \\ %{}) do
    %__MODULE__{
      id: attrs[:id] || PkiMnesia.Id.generate(),
      ceremony_id: attrs[:ceremony_id],
      entries: Map.get(attrs, :entries, []),
      finalized_at: attrs[:finalized_at],
      inserted_at: attrs[:inserted_at] || DateTime.utc_now() |> DateTime.truncate(:second)
    }
  end
end
