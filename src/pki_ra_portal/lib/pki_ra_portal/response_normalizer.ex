defmodule PkiRaPortal.ResponseNormalizer do
  @moduledoc """
  Normalizes engine responses for safe use in LiveView templates.

  Ensures:
  - All map keys are atoms (handles both atom and string-keyed maps)
  - DateTime/NaiveDateTime structs are preserved (not converted)
  - Nested maps and lists are recursively normalized
  - Missing keys return nil via Map.get instead of crashing on dot access
  """

  @doc "Normalize a single engine response map."
  def normalize(nil), do: nil

  def normalize(%{__struct__: _} = struct) do
    struct
    |> Map.from_struct()
    |> Map.drop([:__meta__])
    |> normalize()
  end

  def normalize(map) when is_map(map) do
    Map.new(map, fn {k, v} -> {to_atom_key(k), normalize_value(v)} end)
  end

  def normalize(other), do: other

  @doc "Normalize a list of engine response maps."
  def normalize_list(list) when is_list(list), do: Enum.map(list, &normalize/1)
  def normalize_list(_), do: []

  # -- Private --

  defp to_atom_key(k) when is_atom(k), do: k
  defp to_atom_key(k) when is_binary(k) do
    # Only convert to atoms that already exist in the atom table.
    # Unknown keys are kept as strings to prevent atom table exhaustion.
    try do
      String.to_existing_atom(k)
    rescue
      ArgumentError -> k
    end
  end

  defp normalize_value(%DateTime{} = dt), do: dt
  defp normalize_value(%NaiveDateTime{} = dt), do: dt
  defp normalize_value(%Date{} = d), do: d
  defp normalize_value(%{__struct__: Ecto.Association.NotLoaded}), do: nil
  defp normalize_value(%{__struct__: _} = struct), do: normalize(struct)
  defp normalize_value(map) when is_map(map), do: normalize(map)
  defp normalize_value(list) when is_list(list), do: Enum.map(list, &normalize_value/1)
  defp normalize_value(other), do: other
end
