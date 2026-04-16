defmodule PkiMnesia.Repo do
  @moduledoc """
  Generic CRUD operations over Mnesia tables storing Elixir structs.
  All operations run inside :mnesia.transaction/1.
  """

  alias PkiMnesia.Schema

  @doc "Insert a struct into its corresponding Mnesia table."
  @spec insert(struct()) :: {:ok, struct()} | {:error, term()}
  def insert(%{__struct__: mod} = struct) do
    table = Schema.table_name(mod)
    record = struct_to_record(table, struct)

    case :mnesia.transaction(fn -> :mnesia.write(record) end) do
      {:atomic, :ok} -> {:ok, struct}
      {:aborted, reason} -> {:error, reason}
    end
  end

  @doc "Get a struct by its primary key (id)."
  @spec get(module(), binary()) :: {:ok, struct()} | {:ok, nil} | {:error, term()}
  def get(struct_mod, id) do
    table = Schema.table_name(struct_mod)

    case :mnesia.transaction(fn -> :mnesia.read(table, id) end) do
      {:atomic, [record]} -> {:ok, record_to_struct(struct_mod, record)}
      {:atomic, []} -> {:ok, nil}
      {:aborted, reason} -> {:error, reason}
    end
  end

  @doc "Get a struct by an indexed field value. Returns first match or nil."
  @spec get_by(module(), atom(), term()) :: {:ok, struct()} | {:ok, nil} | {:error, term()}
  def get_by(struct_mod, field, value) do
    table = Schema.table_name(struct_mod)

    case :mnesia.transaction(fn -> :mnesia.index_read(table, value, field) end) do
      {:atomic, [record | _]} -> {:ok, record_to_struct(struct_mod, record)}
      {:atomic, []} -> {:ok, nil}
      {:aborted, reason} -> {:error, reason}
    end
  end

  @doc "Update specific fields of a struct already in Mnesia."
  @spec update(struct(), map()) :: {:ok, struct()} | {:error, term()}
  def update(%{__struct__: mod, id: id} = struct, changes) when is_map(changes) do
    table = Schema.table_name(mod)

    case :mnesia.transaction(fn ->
      case :mnesia.read(table, id) do
        [_existing] ->
          updated = Map.merge(struct, changes)
          record = struct_to_record(table, updated)
          :mnesia.write(record)
          updated

        [] ->
          :mnesia.abort(:not_found)
      end
    end) do
      {:atomic, updated} -> {:ok, updated}
      {:aborted, :not_found} -> {:error, :not_found}
      {:aborted, reason} -> {:error, reason}
    end
  end

  @doc "Delete a struct from Mnesia by id."
  @spec delete(module(), binary()) :: :ok | {:error, term()}
  def delete(struct_mod, id) do
    table = Schema.table_name(struct_mod)

    case :mnesia.transaction(fn -> :mnesia.delete({table, id}) end) do
      {:atomic, :ok} -> :ok
      {:aborted, reason} -> {:error, reason}
    end
  end

  @doc "Return all records for a table as structs."
  @spec all(module()) :: {:ok, [struct()]} | {:error, term()}
  def all(struct_mod) do
    table = Schema.table_name(struct_mod)

    case :mnesia.transaction(fn ->
      :mnesia.foldl(fn record, acc -> [record | acc] end, [], table)
    end) do
      {:atomic, records} ->
        {:ok, Enum.map(records, &record_to_struct(struct_mod, &1))}

      {:aborted, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Return all records matching a filter function.
  The filter receives a struct and returns true/false.
  """
  @spec where(module(), (struct() -> boolean())) :: {:ok, [struct()]} | {:error, term()}
  def where(struct_mod, filter_fn) do
    table = Schema.table_name(struct_mod)

    case :mnesia.transaction(fn ->
      :mnesia.foldl(fn record, acc ->
        struct = record_to_struct(struct_mod, record)
        if filter_fn.(struct), do: [struct | acc], else: acc
      end, [], table)
    end) do
      {:atomic, results} -> {:ok, results}
      {:aborted, reason} -> {:error, reason}
    end
  end

  @doc """
  Execute an arbitrary function inside a Mnesia transaction.
  Returns {:ok, result} or {:error, reason}.
  """
  @spec transaction(fun()) :: {:ok, term()} | {:error, term()}
  def transaction(fun) do
    case :mnesia.transaction(fun) do
      {:atomic, result} -> {:ok, result}
      {:aborted, reason} -> {:error, reason}
    end
  end

  # -- Conversion helpers --

  @doc false
  def struct_to_record(table, %{__struct__: mod} = struct) do
    attrs = Schema.struct_attributes(mod)
    values = Enum.map(attrs, fn attr -> Map.get(struct, attr) end)
    List.to_tuple([table | values])
  end

  @doc false
  def record_to_struct(struct_mod, record) when is_tuple(record) do
    [_table | values] = Tuple.to_list(record)
    attrs = Schema.struct_attributes(struct_mod)
    pairs = Enum.zip(attrs, values)
    struct(struct_mod, pairs)
  end
end
