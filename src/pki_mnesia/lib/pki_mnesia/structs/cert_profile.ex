defmodule PkiMnesia.Structs.CertProfile do
  @moduledoc "Certificate profile configuration."

  defstruct [
    :id,
    :ra_instance_id,
    :name,
    :issuer_key_id,
    :subject_dn_policy,
    :key_usage,
    :extended_key_usage,
    :validity_days,
    :validity_policy,
    :approval_mode,
    :crl_policy,
    :ocsp_policy,
    :notification_profile,
    :renewal_policy,
    :status,
    :inserted_at,
    :updated_at
  ]

  @type t :: %__MODULE__{
    id: binary(),
    ra_instance_id: binary(),
    name: String.t(),
    issuer_key_id: binary() | nil,
    subject_dn_policy: map(),
    key_usage: [String.t()],
    extended_key_usage: [String.t()],
    validity_days: integer(),
    validity_policy: map(),
    approval_mode: String.t(),
    crl_policy: map(),
    ocsp_policy: map(),
    notification_profile: map(),
    renewal_policy: map(),
    status: String.t(),
    inserted_at: DateTime.t(),
    updated_at: DateTime.t()
  }

  def new(attrs \\ %{}) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    %__MODULE__{
      id: attrs[:id] || PkiMnesia.Id.generate(),
      ra_instance_id: attrs[:ra_instance_id],
      name: attrs[:name],
      issuer_key_id: attrs[:issuer_key_id],
      subject_dn_policy: Map.get(attrs, :subject_dn_policy, %{}),
      key_usage: Map.get(attrs, :key_usage, []),
      extended_key_usage: Map.get(attrs, :extended_key_usage, []),
      validity_days: Map.get(attrs, :validity_days, 365),
      validity_policy: Map.get(attrs, :validity_policy, %{}),
      approval_mode: Map.get(attrs, :approval_mode, "manual"),
      crl_policy: Map.get(attrs, :crl_policy, %{}),
      ocsp_policy: Map.get(attrs, :ocsp_policy, %{}),
      notification_profile: Map.get(attrs, :notification_profile, %{}),
      renewal_policy: Map.get(attrs, :renewal_policy, %{}),
      status: Map.get(attrs, :status, "active"),
      inserted_at: attrs[:inserted_at] || now,
      updated_at: attrs[:updated_at] || now
    }
  end
end
