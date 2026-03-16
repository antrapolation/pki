defmodule PkiRaEngine.QueryHelpers do
  import Ecto.Query

  def apply_eq_filters(query, []), do: query

  def apply_eq_filters(query, [{field, value} | rest]) do
    query
    |> where([r], field(r, ^field) == ^value)
    |> apply_eq_filters(rest)
  end
end
