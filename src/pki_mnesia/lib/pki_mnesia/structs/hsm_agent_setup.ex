defmodule PkiMnesia.Structs.HsmAgentSetup do
  @moduledoc """
  Wizard draft state for the CA admin HSM agent setup flow.

  Persists across sessions so the admin can pause at the "waiting for agent"
  step and resume when the agent operator reports back.

  `server_key_pem` is wiped on completion — it lives only as long as setup
  is in progress.
  """

  @fields [
    :id,
    :ca_instance_id,
    :tenant_id,
    :agent_id,
    :gateway_port,
    :cert_mode,
    :server_cert_pem,
    :server_key_pem,
    :ca_cert_pem,
    :auth_token_hash,
    :key_labels,
    :selected_key_label,
    :expected_agent_id,
    :status,
    :inserted_at,
    :updated_at
  ]
  def fields, do: @fields

  defstruct @fields

  @type t :: %__MODULE__{
          id: binary(),
          ca_instance_id: binary(),
          tenant_id: binary() | nil,
          agent_id: binary() | nil,
          gateway_port: integer() | nil,
          cert_mode: String.t() | nil,
          server_cert_pem: binary() | nil,
          server_key_pem: binary() | nil,
          ca_cert_pem: binary() | nil,
          auth_token_hash: binary() | nil,
          key_labels: [String.t()],
          selected_key_label: binary() | nil,
          expected_agent_id: binary() | nil,
          status: String.t(),
          inserted_at: DateTime.t(),
          updated_at: DateTime.t()
        }

  def new(attrs \\ %{}) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    %__MODULE__{
      id: attrs[:id] || PkiMnesia.Id.generate(),
      ca_instance_id: attrs[:ca_instance_id],
      tenant_id: attrs[:tenant_id],
      agent_id: attrs[:agent_id],
      gateway_port: attrs[:gateway_port],
      cert_mode: attrs[:cert_mode] || "generated",
      server_cert_pem: attrs[:server_cert_pem],
      server_key_pem: attrs[:server_key_pem],
      ca_cert_pem: attrs[:ca_cert_pem],
      auth_token_hash: attrs[:auth_token_hash],
      key_labels: attrs[:key_labels] || [],
      selected_key_label: attrs[:selected_key_label],
      expected_agent_id: attrs[:expected_agent_id],
      status: attrs[:status] || "pending_agent",
      inserted_at: attrs[:inserted_at] || now,
      updated_at: attrs[:updated_at] || now
    }
  end
end
