defmodule PkiCaPortal.CustodianPasswordStore do
  @moduledoc """
  ETS-backed in-memory store for custodian passwords during ceremony preparation.

  Passwords are NEVER written to disk or DB. They exist in memory only
  for the duration of the preparation phase, then are wiped after share
  encryption or on ceremony failure/expiry.
  """

  use GenServer

  @table :ceremony_custodian_passwords

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def store_password(ceremony_id, user_id, password) do
    GenServer.call(__MODULE__, {:store_password, ceremony_id, user_id, password})
  end

  def get_password(ceremony_id, user_id) do
    case :ets.lookup(@table, {ceremony_id, user_id}) do
      [{{^ceremony_id, ^user_id}, password}] -> {:ok, password}
      [] -> {:error, :not_found}
    end
  end

  def get_all_passwords(ceremony_id) do
    :ets.tab2list(@table)
    |> Enum.filter(fn {{cid, _uid}, _pw} -> cid == ceremony_id end)
    |> Enum.map(fn {{_cid, uid}, pw} -> {uid, pw} end)
  end

  def has_all_passwords?(ceremony_id, user_ids) do
    stored = get_all_passwords(ceremony_id) |> Enum.map(&elem(&1, 0))
    Enum.all?(user_ids, &(&1 in stored))
  end

  def wipe_ceremony(ceremony_id) do
    GenServer.call(__MODULE__, {:wipe_ceremony, ceremony_id})
  end

  def clear_all do
    GenServer.call(__MODULE__, :clear_all)
  end

  @impl true
  def init(_opts) do
    table = :ets.new(@table, [:named_table, :set, :protected, read_concurrency: true])
    {:ok, %{table: table}}
  end

  @impl true
  def handle_call({:store_password, ceremony_id, user_id, password}, _from, state) do
    :ets.insert(@table, {{ceremony_id, user_id}, password})
    {:reply, :ok, state}
  end

  def handle_call({:wipe_ceremony, ceremony_id}, _from, state) do
    :ets.tab2list(@table)
    |> Enum.filter(fn {{cid, _uid}, _pw} -> cid == ceremony_id end)
    |> Enum.each(fn {key, _pw} -> :ets.delete(@table, key) end)
    {:reply, :ok, state}
  end

  def handle_call(:clear_all, _from, state) do
    :ets.delete_all_objects(@table)
    {:reply, :ok, state}
  end
end
