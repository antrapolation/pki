defmodule PkiMnesia.Structs.DcvChallenge do
  @moduledoc "Domain control validation challenge."

  defstruct [
    :id,
    :csr_request_id,
    :domain,
    :challenge_type,
    :challenge_token,
    :status,
    :verified_at,
    :expires_at,
    :inserted_at
  ]

  @type t :: %__MODULE__{
    id: binary(),
    csr_request_id: binary(),
    domain: String.t(),
    challenge_type: String.t(),
    challenge_token: String.t(),
    status: String.t(),
    verified_at: DateTime.t() | nil,
    expires_at: DateTime.t(),
    inserted_at: DateTime.t()
  }

  def new(attrs \\ %{}) do
    %__MODULE__{
      id: attrs[:id] || PkiMnesia.Id.generate(),
      csr_request_id: attrs[:csr_request_id],
      domain: attrs[:domain],
      challenge_type: Map.get(attrs, :challenge_type, "dns"),
      challenge_token: attrs[:challenge_token] || Base.encode64(:crypto.strong_rand_bytes(32)),
      status: Map.get(attrs, :status, "pending"),
      verified_at: attrs[:verified_at],
      expires_at: attrs[:expires_at] || DateTime.utc_now() |> DateTime.add(86400, :second) |> DateTime.truncate(:second),
      inserted_at: attrs[:inserted_at] || DateTime.utc_now() |> DateTime.truncate(:second)
    }
  end
end
