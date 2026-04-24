defmodule PkiMnesia.Structs.ThresholdShare do
  @moduledoc """
  Custodian threshold share. Keyed by custodian_name (string), NOT a user FK.

  ## Field lifecycle

  `password_hash` is **ceremony-scoped**. It holds a PBKDF2 hash of the
  custodian's per-ceremony password only during the brief window between
  `CeremonyOrchestrator.accept_share/3` and `execute_keygen/2`'s
  password-verification gate. Once `encrypt_and_commit` writes
  `encrypted_share`, the orchestrator wipes `password_hash` to nil — the
  authoritative record is the AES-GCM ciphertext in `encrypted_share`,
  and activation-time decryption authenticates the submitted password
  via the GCM tag (no separate hash needed).

  Observed field combinations by status:

      status "pending":   encrypted_share=nil,        password_hash=nil
      status "accepted":  encrypted_share=nil,        password_hash=<48-byte hash>
      status "active":    encrypted_share=<ciphertext>, password_hash=nil
  """

  @fields [:id, :issuer_key_id, :custodian_name, :share_index, :encrypted_share,
           :share_signature, :password_hash, :min_shares, :total_shares, :status,
           :inserted_at, :updated_at]
  def fields, do: @fields

  defstruct @fields

  @type t :: %__MODULE__{
    id: binary(),
    issuer_key_id: binary(),
    custodian_name: String.t(),
    share_index: integer(),
    encrypted_share: binary() | nil,
    share_signature: binary() | nil,
    password_hash: binary() | nil,
    min_shares: integer(),
    total_shares: integer(),
    status: String.t(),
    inserted_at: DateTime.t(),
    updated_at: DateTime.t()
  }

  @doc "Validates required fields before Mnesia write."
  def validate(%__MODULE__{} = s) do
    missing =
      [{:issuer_key_id, s.issuer_key_id}, {:custodian_name, s.custodian_name}, {:share_index, s.share_index}]
      |> Enum.filter(fn {_k, v} -> is_nil(v) end)
      |> Enum.map(fn {k, _v} -> k end)

    if missing == [], do: :ok, else: {:error, {:missing_fields, missing}}
  end

  def new(attrs \\ %{}) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    %__MODULE__{
      id: attrs[:id] || PkiMnesia.Id.generate(),
      issuer_key_id: attrs[:issuer_key_id],
      custodian_name: attrs[:custodian_name],
      share_index: attrs[:share_index],
      encrypted_share: attrs[:encrypted_share],
      share_signature: attrs[:share_signature],
      password_hash: attrs[:password_hash],
      min_shares: attrs[:min_shares],
      total_shares: attrs[:total_shares],
      status: Map.get(attrs, :status, "pending"),
      inserted_at: attrs[:inserted_at] || now,
      updated_at: attrs[:updated_at] || now
    }
  end
end
