defmodule PkiAuditTrail.Hasher do
  @moduledoc """
  Computes SHA3-256 hash for audit events, creating a tamper-evident chain.
  Hash input: event_id || timestamp || node_name || actor_did || action ||
              resource_type || resource_id || details_json || prev_hash
  """

  @genesis_hash String.duplicate("0", 64)

  def genesis_hash, do: @genesis_hash

  def compute_hash(%{} = attrs) do
    payload =
      [
        to_string(attrs.event_id),
        DateTime.to_iso8601(attrs.timestamp),
        to_string(attrs.node_name),
        to_string(attrs.actor_did),
        to_string(attrs.action),
        to_string(attrs.resource_type),
        to_string(attrs.resource_id),
        Jason.encode!(attrs[:details] || %{}),
        to_string(attrs.prev_hash)
      ]
      |> Enum.join("|")

    :crypto.hash(:sha3_256, payload)
    |> Base.encode16(case: :lower)
  end
end
