defmodule PkiMnesia.Structs.IssuerKey do
  @moduledoc "Issuer key record with ceremony mode and lifecycle status."

  @fields [:id, :ca_instance_id, :key_alias, :algorithm, :status, :is_root,
           :ceremony_mode, :key_mode, :keystore_ref, :certificate_der, :certificate_pem,
           :csr_pem, :subject_dn, :fingerprint, :threshold_config,
           :keystore_type, :hsm_config, :hsm_key_handle,
           :inserted_at, :updated_at]
  def fields, do: @fields

  defstruct @fields

  @type t :: %__MODULE__{
    id: binary(),
    ca_instance_id: binary(),
    key_alias: String.t(),
    algorithm: String.t(),
    status: String.t(),
    is_root: boolean(),
    ceremony_mode: atom(),
    key_mode: String.t(),
    keystore_ref: binary() | nil,
    certificate_der: binary() | nil,
    certificate_pem: String.t() | nil,
    csr_pem: String.t() | nil,
    subject_dn: String.t() | nil,
    fingerprint: String.t() | nil,
    threshold_config: map(),
    keystore_type: :software | :local_hsm | :remote_hsm,
    hsm_config: map(),
    hsm_key_handle: binary() | nil,
    inserted_at: DateTime.t(),
    updated_at: DateTime.t()
  }

  @doc "Validates required fields before Mnesia write."
  def validate(%__MODULE__{} = s) do
    missing =
      [{:ca_instance_id, s.ca_instance_id}, {:algorithm, s.algorithm}]
      |> Enum.filter(fn {_k, v} -> is_nil(v) end)
      |> Enum.map(fn {k, _v} -> k end)

    if missing == [], do: :ok, else: {:error, {:missing_fields, missing}}
  end

  def new(attrs \\ %{}) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    %__MODULE__{
      id: attrs[:id] || PkiMnesia.Id.generate(),
      ca_instance_id: attrs[:ca_instance_id],
      key_alias: attrs[:key_alias],
      algorithm: attrs[:algorithm],
      status: Map.get(attrs, :status, "pending"),
      is_root: Map.get(attrs, :is_root, true),
      ceremony_mode: Map.get(attrs, :ceremony_mode, :full),
      key_mode: Map.get(attrs, :key_mode, "threshold"),
      keystore_ref: attrs[:keystore_ref],
      certificate_der: attrs[:certificate_der],
      certificate_pem: attrs[:certificate_pem],
      csr_pem: attrs[:csr_pem],
      subject_dn: attrs[:subject_dn],
      fingerprint: attrs[:fingerprint],
      threshold_config: Map.get(attrs, :threshold_config, %{k: 2, n: 3}),
      keystore_type: Map.get(attrs, :keystore_type, :software),
      hsm_config: Map.get(attrs, :hsm_config, %{}),
      hsm_key_handle: attrs[:hsm_key_handle],
      inserted_at: attrs[:inserted_at] || now,
      updated_at: attrs[:updated_at] || now
    }
  end
end
