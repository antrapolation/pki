defmodule PkiAuditTrail do
  @moduledoc """
  Tamper-evident, hash-chained audit logging for PKI services.

  ## Usage

      PkiAuditTrail.log(
        %{actor_did: "did:ssdid:admin1", actor_role: "ca_admin", node_name: "node1"},
        "certificate_issued",
        %{resource_type: "certificate", resource_id: "cert-001", details: %{"serial" => "ABC"}}
      )

      PkiAuditTrail.verify_chain()
      PkiAuditTrail.query(action: "certificate_issued", actor_did: "did:ssdid:admin1")
  """

  import Ecto.Query
  alias PkiAuditTrail.{AuditEvent, Logger, Repo, Verifier}

  defdelegate log(actor, action, resource), to: Logger
  defdelegate verify_chain(), to: Verifier

  def query(filters \\ []) do
    AuditEvent
    |> apply_filters(filters)
    |> order_by(asc: :id)
    |> Repo.all()
  end

  defp apply_filters(query, []), do: query
  defp apply_filters(query, [{:action, action} | rest]),
    do: query |> where([e], e.action == ^action) |> apply_filters(rest)
  defp apply_filters(query, [{:actor_did, did} | rest]),
    do: query |> where([e], e.actor_did == ^did) |> apply_filters(rest)
  defp apply_filters(query, [{:resource_type, type} | rest]),
    do: query |> where([e], e.resource_type == ^type) |> apply_filters(rest)
  defp apply_filters(query, [{:resource_id, id} | rest]),
    do: query |> where([e], e.resource_id == ^id) |> apply_filters(rest)
  defp apply_filters(query, [{:since, since} | rest]),
    do: query |> where([e], e.timestamp >= ^since) |> apply_filters(rest)
  defp apply_filters(query, [{:until, until} | rest]),
    do: query |> where([e], e.timestamp <= ^until) |> apply_filters(rest)
  defp apply_filters(query, [_ | rest]), do: apply_filters(query, rest)
end
