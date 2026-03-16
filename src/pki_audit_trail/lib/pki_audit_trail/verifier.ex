defmodule PkiAuditTrail.Verifier do
  @moduledoc """
  Verifies the integrity of the audit event hash chain.
  Walks the entire chain from first event to last, checking:
  1. Each event's hash matches its recomputed hash
  2. Each event's prev_hash matches the previous event's event_hash
  """

  import Ecto.Query

  alias PkiAuditTrail.{AuditEvent, Hasher, Repo}

  def verify_chain do
    events = Repo.all(from e in AuditEvent, order_by: [asc: e.id])

    case events do
      [] -> {:ok, 0}
      events -> verify_events(events, Hasher.genesis_hash(), 0)
    end
  end

  defp verify_events([], _expected_prev_hash, count), do: {:ok, count}

  defp verify_events([event | rest], expected_prev_hash, count) do
    if event.prev_hash != expected_prev_hash do
      {:error, {:broken_chain, event.event_id}}
    else
      recomputed =
        Hasher.compute_hash(%{
          event_id: event.event_id,
          timestamp: event.timestamp,
          node_name: event.node_name,
          actor_did: event.actor_did,
          action: event.action,
          resource_type: event.resource_type,
          resource_id: event.resource_id,
          details: event.details,
          prev_hash: event.prev_hash
        })

      if recomputed != event.event_hash do
        {:error, {:tampered_hash, event.event_id}}
      else
        verify_events(rest, event.event_hash, count + 1)
      end
    end
  end
end
