defmodule PkiMnesia.Structs.IssuedCertificate do
  @moduledoc "Signed certificate record. Stored as disc_only_copies (can grow large)."

  @fields [:id, :serial_number, :issuer_key_id, :subject_dn, :cert_der,
           :cert_pem, :not_before, :not_after, :cert_profile_id, :csr_fingerprint,
           :status, :revoked_at, :revocation_reason, :inserted_at, :updated_at]
  def fields, do: @fields

  defstruct @fields

  @type t :: %__MODULE__{
    id: binary(),
    serial_number: String.t(),
    issuer_key_id: binary(),
    subject_dn: String.t(),
    cert_der: binary(),
    cert_pem: String.t(),
    not_before: DateTime.t(),
    not_after: DateTime.t(),
    cert_profile_id: binary() | nil,
    csr_fingerprint: String.t() | nil,
    status: String.t(),
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
      subject_dn: attrs[:subject_dn],
      cert_der: attrs[:cert_der],
      cert_pem: attrs[:cert_pem],
      not_before: attrs[:not_before] || now,
      not_after: attrs[:not_after],
      cert_profile_id: attrs[:cert_profile_id],
      csr_fingerprint: attrs[:csr_fingerprint],
      status: Map.get(attrs, :status, "active"),
      revoked_at: attrs[:revoked_at],
      revocation_reason: attrs[:revocation_reason],
      inserted_at: attrs[:inserted_at] || now,
      updated_at: attrs[:updated_at] || now
    }
  end
end
