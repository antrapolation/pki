defmodule PkiMnesia.Structs.CeremonyParticipant do
  @moduledoc """
  Ceremony participant: custodian or auditor.
  Name is entered during ceremony -- NOT a portal user account FK.
  """

  defstruct [
    :id,
    :ceremony_id,
    :name,
    :role,
    :identity_verified_by,
    :identity_verified_at,
    :share_accepted_at,
    :inserted_at
  ]

  @type t :: %__MODULE__{
    id: binary(),
    ceremony_id: binary(),
    name: String.t(),
    role: atom(),
    identity_verified_by: String.t() | nil,
    identity_verified_at: DateTime.t() | nil,
    share_accepted_at: DateTime.t() | nil,
    inserted_at: DateTime.t()
  }

  def new(attrs \\ %{}) do
    %__MODULE__{
      id: attrs[:id] || PkiMnesia.Id.generate(),
      ceremony_id: attrs[:ceremony_id],
      name: attrs[:name],
      role: attrs[:role],
      identity_verified_by: attrs[:identity_verified_by],
      identity_verified_at: attrs[:identity_verified_at],
      share_accepted_at: attrs[:share_accepted_at],
      inserted_at: attrs[:inserted_at] || DateTime.utc_now() |> DateTime.truncate(:second)
    }
  end
end
