defmodule PkiMnesia.Structs.CeremonyTranscript do
  @moduledoc """
  Serialized event log for ceremony PDF generation.
  Entries are a list of maps: %{timestamp, actor, action, details, prev_hash, event_hash}.

  Each entry is hash-chained: event_hash = sha256(prev_hash <> json(content_fields)).
  This makes the transcript tamper-evident — any alteration breaks the chain.
  The genesis entry uses <<0::256>> as prev_hash.
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

  @genesis_hash <<0::256>>

  def new(attrs \\ %{}) do
    %__MODULE__{
      id: attrs[:id] || PkiMnesia.Id.generate(),
      ceremony_id: attrs[:ceremony_id],
      entries: Map.get(attrs, :entries, []),
      finalized_at: attrs[:finalized_at],
      inserted_at: attrs[:inserted_at] || DateTime.utc_now() |> DateTime.truncate(:second)
    }
  end

  @doc """
  Appends a new entry to the transcript, computing a hash chain over
  prev_hash and the entry content fields (timestamp, actor, action, details).

  The entry map should be:
    %{"timestamp" => ..., "actor" => ..., "action" => ..., "details" => ...}
  """
  @spec append(t(), map()) :: t()
  def append(%__MODULE__{} = transcript, event_map) when is_map(event_map) do
    prev =
      case List.last(transcript.entries || []) do
        nil -> @genesis_hash
        # Tolerate pre-E4.1 entries written with atom keys and no event_hash.
        last -> Map.get(last, "event_hash") || Map.get(last, :event_hash) || @genesis_hash
      end

    event_hash = :crypto.hash(:sha256, prev <> Jason.encode!(event_map))
    entry = Map.merge(event_map, %{"prev_hash" => prev, "event_hash" => event_hash})
    %{transcript | entries: (transcript.entries || []) ++ [entry]}
  end

  @doc """
  Walks all entries and recomputes each event_hash from the stored prev_hash
  and the content fields (everything except prev_hash and event_hash).

  Returns :ok if the chain is intact, or {:error, {:broken_at, index}} where
  index is 1-based, on the first mismatch.
  """
  @spec verify_chain(t()) :: :ok | {:error, {:broken_at, pos_integer()}}
  def verify_chain(%__MODULE__{entries: entries}) do
    entries
    |> Enum.with_index(1)
    |> Enum.reduce_while(:ok, fn {entry, idx}, :ok ->
      case {Map.fetch(entry, "prev_hash"), Map.fetch(entry, "event_hash")} do
        {{:ok, prev_hash}, {:ok, stored_hash}} ->
          content = Map.drop(entry, ["prev_hash", "event_hash"])
          expected = :crypto.hash(:sha256, prev_hash <> Jason.encode!(content))

          if expected == stored_hash do
            {:cont, :ok}
          else
            {:halt, {:error, {:broken_at, idx}}}
          end

        _ ->
          # Pre-E4.1 entry without hash fields — skip verification for this entry.
          {:cont, :ok}
      end
    end)
  end
end
