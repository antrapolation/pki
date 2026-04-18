defmodule PkiMnesia.Structs.BackupRecord do
  @moduledoc "Tracks Mnesia backup history for health reporting."

  @fields [:id, :timestamp, :type, :size_bytes, :location, :status, :error, :inserted_at]
  def fields, do: @fields

  defstruct @fields

  @type t :: %__MODULE__{
    id: binary(),
    timestamp: DateTime.t(),
    type: String.t(),         # "local" | "remote"
    size_bytes: integer(),
    location: String.t(),     # file path or S3 URL
    status: String.t(),       # "completed" | "failed"
    error: String.t() | nil,
    inserted_at: DateTime.t()
  }

  def new(attrs \\ %{}) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    %__MODULE__{
      id: attrs[:id] || PkiMnesia.Id.generate(),
      timestamp: attrs[:timestamp] || now,
      type: attrs[:type] || "local",
      size_bytes: attrs[:size_bytes] || 0,
      location: attrs[:location] || "",
      status: attrs[:status] || "completed",
      error: attrs[:error],
      inserted_at: attrs[:inserted_at] || now
    }
  end
end
