defmodule PkiMnesia.Structs.KeyCeremony do
  @moduledoc "Key ceremony state tracking."

  @fields [:id, :ca_instance_id, :issuer_key_id, :ceremony_type, :status,
           :algorithm, :threshold_k, :threshold_n, :domain_info, :initiated_by,
           :keystore_mode, :window_expires_at, :inserted_at, :updated_at]
  def fields, do: @fields

  defstruct @fields

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
    # One of "software" | "softhsm" | "hsm".
    # Drives how the private key is stored after keygen:
    #   "software"  — in-BEAM encrypted store (dev/test only)
    #   "softhsm"   — PKCS#11 via SoftHSM (default; staging/prod without real HSM)
    #   "hsm"       — PKCS#11 via real hardware HSM (required in prod)
    # IssuerKey.keystore_type is derived from this value at activation time.
    keystore_mode: String.t(),
    window_expires_at: DateTime.t() | nil,
    inserted_at: DateTime.t(),
    updated_at: DateTime.t()
  }

  @valid_keystore_modes ~w(software softhsm hsm)

  @doc "Valid keystore_mode values for a ceremony."
  def valid_keystore_modes, do: @valid_keystore_modes

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
      keystore_mode: Map.get(attrs, :keystore_mode, "softhsm"),
      window_expires_at: attrs[:window_expires_at],
      inserted_at: attrs[:inserted_at] || now,
      updated_at: attrs[:updated_at] || now
    }
  end
end
