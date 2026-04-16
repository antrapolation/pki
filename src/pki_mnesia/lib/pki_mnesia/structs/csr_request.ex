defmodule PkiMnesia.Structs.CsrRequest do
  @moduledoc "CSR submission record. Stored as disc_only_copies (can grow)."

  defstruct [
    :id,
    :csr_pem,
    :csr_der,
    :cert_profile_id,
    :subject_dn,
    :status,
    :submitted_at,
    :submitted_by_key_id,
    :reviewed_by,
    :reviewed_at,
    :rejection_reason,
    :issued_cert_serial,
    :inserted_at,
    :updated_at
  ]

  @type t :: %__MODULE__{
    id: binary(),
    csr_pem: String.t(),
    csr_der: binary() | nil,
    cert_profile_id: binary(),
    subject_dn: String.t(),
    status: String.t(),
    submitted_at: DateTime.t(),
    submitted_by_key_id: binary() | nil,
    reviewed_by: String.t() | nil,
    reviewed_at: DateTime.t() | nil,
    rejection_reason: String.t() | nil,
    issued_cert_serial: String.t() | nil,
    inserted_at: DateTime.t(),
    updated_at: DateTime.t()
  }

  def new(attrs \\ %{}) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    %__MODULE__{
      id: attrs[:id] || PkiMnesia.Id.generate(),
      csr_pem: attrs[:csr_pem],
      csr_der: attrs[:csr_der],
      cert_profile_id: attrs[:cert_profile_id],
      subject_dn: Map.get(attrs, :subject_dn, "CN=unknown"),
      status: Map.get(attrs, :status, "pending"),
      submitted_at: attrs[:submitted_at] || now,
      submitted_by_key_id: attrs[:submitted_by_key_id],
      reviewed_by: attrs[:reviewed_by],
      reviewed_at: attrs[:reviewed_at],
      rejection_reason: attrs[:rejection_reason],
      issued_cert_serial: attrs[:issued_cert_serial],
      inserted_at: attrs[:inserted_at] || now,
      updated_at: attrs[:updated_at] || now
    }
  end
end
