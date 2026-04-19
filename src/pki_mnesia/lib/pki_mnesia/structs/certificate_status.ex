defmodule PkiMnesia.Structs.CertificateStatus do
  @moduledoc "Certificate revocation status for OCSP/CRL. Stored as disc_only_copies."

  @fields [:id, :serial_number, :issuer_key_id, :status, :not_after,
           :revoked_at, :revocation_reason, :inserted_at, :updated_at]
  def fields, do: @fields

  defstruct @fields

  @type t :: %__MODULE__{
    id: binary(),
    serial_number: String.t(),
    issuer_key_id: binary(),
    status: String.t(),
    not_after: DateTime.t() | nil,
    revoked_at: DateTime.t() | nil,
    revocation_reason: String.t() | nil,
    inserted_at: DateTime.t(),
    updated_at: DateTime.t()
  }

  def new(attrs \\ %{}) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    %__MODULE__{
      id: attrs[:id] || PkiMnesia.Id.generate(),
      serial_number: attrs[:serial_number],
      issuer_key_id: attrs[:issuer_key_id],
      status: Map.get(attrs, :status, "active"),
      not_after: attrs[:not_after],
      revoked_at: attrs[:revoked_at],
      revocation_reason: attrs[:revocation_reason],
      inserted_at: attrs[:inserted_at] || now,
      updated_at: attrs[:updated_at] || now
    }
  end
end
