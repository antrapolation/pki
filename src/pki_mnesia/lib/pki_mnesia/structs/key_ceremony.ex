defmodule PkiMnesia.Structs.KeyCeremony do
  @moduledoc "Key ceremony state tracking."

  defstruct [
    :id,
    :ca_instance_id,
    :issuer_key_id,
    :ceremony_type,
    :status,
    :algorithm,
    :threshold_k,
    :threshold_n,
    :domain_info,
    :initiated_by,
    :window_expires_at,
    :inserted_at,
    :updated_at
  ]

  @type t :: %__MODULE__{
    id: binary(),
    ca_instance_id: binary(),
    issuer_key_id: binary(),
    ceremony_type: String.t(),
    status: String.t(),
    algorithm: String.t(),
    threshold_k: integer(),
    threshold_n: integer(),
    domain_info: map(),
    initiated_by: String.t(),
    window_expires_at: DateTime.t() | nil,
    inserted_at: DateTime.t(),
    updated_at: DateTime.t()
  }

  def new(attrs \\ %{}) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    %__MODULE__{
      id: attrs[:id] || PkiMnesia.Id.generate(),
      ca_instance_id: attrs[:ca_instance_id],
      issuer_key_id: attrs[:issuer_key_id],
      ceremony_type: Map.get(attrs, :ceremony_type, "sync"),
      status: Map.get(attrs, :status, "preparing"),
      algorithm: attrs[:algorithm],
      threshold_k: attrs[:threshold_k],
      threshold_n: attrs[:threshold_n],
      domain_info: Map.get(attrs, :domain_info, %{}),
      initiated_by: attrs[:initiated_by],
      window_expires_at: attrs[:window_expires_at],
      inserted_at: attrs[:inserted_at] || now,
      updated_at: attrs[:updated_at] || now
    }
  end
end
