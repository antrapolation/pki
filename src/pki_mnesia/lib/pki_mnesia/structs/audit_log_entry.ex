defmodule PkiMnesia.Structs.AuditLogEntry do
  @moduledoc """
  Local tenant audit trail entry.

  Also forwarded to the platform node via `PkiTenant.AuditBridge` for
  centralized observability, but the tenant keeps its own copy so the
  portal UI can query without a cross-node roundtrip.
  """

  @fields [
    :id,
    :timestamp,
    :action,
    :category,
    :actor,
    :actor_role,
    :metadata
  ]
  def fields, do: @fields

  defstruct @fields

  @type t :: %__MODULE__{
          id: binary(),
          timestamp: DateTime.t(),
          action: String.t(),
          category: String.t(),
          actor: String.t(),
          actor_role: String.t() | nil,
          metadata: map()
        }

  @doc "Build an entry, supplying defaults. Accepts string or atom keys."
  def new(attrs \\ %{}) do
    %__MODULE__{
      id: fetch(attrs, :id) || PkiMnesia.Id.generate(),
      timestamp: fetch(attrs, :timestamp) || DateTime.utc_now() |> DateTime.truncate(:second),
      action: fetch(attrs, :action) |> to_string_safe(),
      category: fetch(attrs, :category) |> to_string_safe() |> default_category(),
      actor: fetch(attrs, :actor) |> to_string_safe() |> default_actor(),
      actor_role: fetch(attrs, :actor_role) |> to_string_or_nil(),
      metadata: fetch(attrs, :metadata) || %{}
    }
  end

  defp fetch(attrs, key) do
    Map.get(attrs, key) || Map.get(attrs, Atom.to_string(key))
  end

  defp to_string_safe(nil), do: ""
  defp to_string_safe(v) when is_binary(v), do: v
  defp to_string_safe(v) when is_atom(v), do: Atom.to_string(v)
  defp to_string_safe(v), do: to_string(v)

  defp to_string_or_nil(nil), do: nil
  defp to_string_or_nil(""), do: nil
  defp to_string_or_nil(v), do: to_string_safe(v)

  defp default_category(""), do: "general"
  defp default_category(v), do: v

  defp default_actor(""), do: "system"
  defp default_actor(v), do: v
end
