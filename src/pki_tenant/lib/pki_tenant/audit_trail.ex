defmodule PkiTenant.AuditTrail do
  @moduledoc """
  Local Mnesia-backed audit trail for the tenant BEAM.

  Writes go through `PkiTenant.AuditBridge.log/2`, which persists a
  row here and forwards a copy to the platform node. Reads query
  `PkiMnesia.Structs.AuditLogEntry` directly.

  Event shape at write time is flexible — callers pass the action
  string plus a map of attrs. Category / actor are either pulled
  out of the attrs (keys `:category`, `:actor`, `:actor_role`) or
  inferred from the action prefix (see `infer_category/1`).
  """

  alias PkiMnesia.Repo
  alias PkiMnesia.Structs.AuditLogEntry

  @doc """
  Persist an audit event locally. Returns `{:ok, entry}` or
  `{:error, reason}`. Called from `AuditBridge.log/2`.
  """
  @spec record(String.t(), map()) :: {:ok, AuditLogEntry.t()} | {:error, term()}
  def record(action, attrs) when is_binary(action) and is_map(attrs) do
    actor = Map.get(attrs, :actor) || Map.get(attrs, :actor_username) || "system"
    actor_role = Map.get(attrs, :actor_role) || Map.get(attrs, :user_role)

    category =
      Map.get(attrs, :category) ||
        Map.get(attrs, "category") ||
        infer_category(action)

    metadata = Map.drop(attrs, [:actor, :actor_username, :actor_role, :user_role, :category, "category"])

    entry =
      AuditLogEntry.new(%{
        action: action,
        category: category,
        actor: actor,
        actor_role: actor_role,
        metadata: metadata
      })

    Repo.insert(entry)
  end

  @doc """
  List audit events, newest first, with optional filters.

  Supported filters:

    * `:category` — exact match
    * `:action` — exact match
    * `:actor` — substring match (case-sensitive for now)
    * `:date_from` — `Date` or ISO8601 date string, inclusive
    * `:date_to` — `Date` or ISO8601 date string, inclusive (end of day)
  """
  @spec list_events(keyword()) :: [AuditLogEntry.t()]
  def list_events(filters \\ []) do
    case Repo.all(AuditLogEntry) do
      {:ok, list} ->
        list
        |> apply_filters(filters)
        |> Enum.sort_by(& &1.timestamp, {:desc, DateTime})

      _ ->
        []
    end
  end

  @doc """
  Map a raw action string to its high-level category. Used when the
  caller doesn't supply one explicitly.
  """
  @spec infer_category(String.t()) :: String.t()
  def infer_category(action) when is_binary(action) do
    cond do
      String.contains?(action, "ceremony") -> "ca_operations"
      String.contains?(action, "keystore") -> "ca_operations"
      String.contains?(action, "key") -> "ca_operations"
      String.contains?(action, "certificate") -> "ca_operations"
      String.contains?(action, "hsm") -> "ca_operations"
      String.contains?(action, "user") -> "user_management"
      String.contains?(action, "password") -> "user_management"
      String.contains?(action, "profile") -> "user_management"
      String.contains?(action, "login") -> "user_management"
      String.contains?(action, "csr") -> "ra_operations"
      String.contains?(action, "api_key") -> "ra_operations"
      String.contains?(action, "profile_created") -> "ra_operations"
      true -> "general"
    end
  end

  defp apply_filters(events, filters) do
    Enum.reduce(filters, events, fn
      {:category, nil}, acc -> acc
      {:category, ""}, acc -> acc
      {:category, "all"}, acc -> acc
      {:category, cat}, acc -> Enum.filter(acc, &(&1.category == cat))

      {:action, nil}, acc -> acc
      {:action, ""}, acc -> acc
      {:action, act}, acc -> Enum.filter(acc, &(&1.action == act))

      {:actor, nil}, acc -> acc
      {:actor, ""}, acc -> acc
      {:actor, substr}, acc ->
        Enum.filter(acc, &String.contains?(to_string(&1.actor), substr))

      {:date_from, nil}, acc -> acc
      {:date_from, ""}, acc -> acc
      {:date_from, date}, acc ->
        case parse_date(date) do
          {:ok, d} ->
            start_of_day = DateTime.new!(d, ~T[00:00:00], "Etc/UTC")

            Enum.filter(acc, fn e ->
              DateTime.compare(e.timestamp, start_of_day) != :lt
            end)

          _ ->
            acc
        end

      {:date_to, nil}, acc -> acc
      {:date_to, ""}, acc -> acc
      {:date_to, date}, acc ->
        case parse_date(date) do
          {:ok, d} ->
            end_of_day = DateTime.new!(d, ~T[23:59:59], "Etc/UTC")

            Enum.filter(acc, fn e ->
              DateTime.compare(e.timestamp, end_of_day) != :gt
            end)

          _ ->
            acc
        end

      _, acc -> acc
    end)
  end

  defp parse_date(%Date{} = d), do: {:ok, d}

  defp parse_date(str) when is_binary(str) do
    case Date.from_iso8601(str) do
      {:ok, d} -> {:ok, d}
      _ -> :error
    end
  end

  defp parse_date(_), do: :error
end
