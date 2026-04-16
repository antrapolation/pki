defmodule PkiMnesia.Structs.RaCaConnection do
  @moduledoc "Link between RA instance and CA issuer key."

  defstruct [
    :id,
    :ra_instance_id,
    :ca_instance_id,
    :issuer_key_id,
    :status,
    :inserted_at
  ]

  @type t :: %__MODULE__{
    id: binary(),
    ra_instance_id: binary(),
    ca_instance_id: binary(),
    issuer_key_id: binary(),
    status: String.t(),
    inserted_at: DateTime.t()
  }

  def new(attrs \\ %{}) do
    %__MODULE__{
      id: attrs[:id] || PkiMnesia.Id.generate(),
      ra_instance_id: attrs[:ra_instance_id],
      ca_instance_id: attrs[:ca_instance_id],
      issuer_key_id: attrs[:issuer_key_id],
      status: Map.get(attrs, :status, "active"),
      inserted_at: attrs[:inserted_at] || DateTime.utc_now() |> DateTime.truncate(:second)
    }
  end
end
