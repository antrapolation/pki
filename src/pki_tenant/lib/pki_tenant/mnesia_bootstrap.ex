defmodule PkiTenant.MnesiaBootstrap do
  @moduledoc """
  Opens or creates Mnesia tables on tenant boot.
  Uses MNESIA_DIR env var or /var/lib/pki/tenants/<slug>/mnesia/.

  In replica mode (REPLICA_MODE=true), joins an existing primary's Mnesia
  cluster instead of creating a fresh schema. The primary node is read from
  PRIMARY_TENANT_NODE env var.
  """
  use GenServer

  require Logger

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(opts) do
    if System.get_env("REPLICA_MODE") == "true" do
      init_replica(opts)
    else
      init_primary(opts)
    end
  end

  # -- Primary mode (existing behavior, unchanged) --

  defp init_primary(opts) do
    slug = Keyword.get(opts, :slug, "dev")
    mnesia_dir = System.get_env("MNESIA_DIR") || "/var/lib/pki/tenants/#{slug}/mnesia"

    File.mkdir_p!(mnesia_dir)
    Application.put_env(:mnesia, :dir, String.to_charlist(mnesia_dir))

    :mnesia.stop()

    case :mnesia.create_schema([node()]) do
      :ok -> :ok
      {:error, {_, {:already_exists, _}}} -> :ok
      {:error, reason} -> raise "Mnesia schema creation failed: #{inspect(reason)}"
    end

    case :mnesia.start() do
      :ok -> :ok
      {:error, reason} -> raise "Mnesia failed to start: #{inspect(reason)}"
    end

    :ok = PkiMnesia.Schema.create_tables()

    table_names = :mnesia.system_info(:local_tables) -- [:schema]
    :mnesia.wait_for_tables(table_names, 10_000)

    Logger.info("[mnesia_bootstrap] Mnesia started at #{mnesia_dir} with #{length(table_names)} tables")

    {:ok, %{dir: mnesia_dir, mode: :primary}}
  end

  # -- Replica mode --

  defp init_replica(opts) do
    slug = Keyword.get(opts, :slug, "dev")
    mnesia_dir = System.get_env("MNESIA_DIR") || "/var/lib/pki/replicas/#{slug}/mnesia"

    primary_node_str = System.get_env("PRIMARY_TENANT_NODE")

    unless primary_node_str do
      raise "REPLICA_MODE=true but PRIMARY_TENANT_NODE env var is not set"
    end

    primary_node = String.to_atom(primary_node_str)

    File.mkdir_p!(mnesia_dir)
    Application.put_env(:mnesia, :dir, String.to_charlist(mnesia_dir))

    # Do NOT create schema — we join an existing cluster
    case :mnesia.start() do
      :ok -> :ok
      {:error, reason} -> raise "Mnesia failed to start in replica mode: #{inspect(reason)}"
    end

    case PkiMnesia.Schema.add_replica_copies(primary_node) do
      :ok ->
        Logger.info("[mnesia_bootstrap] Started as replica, connected to #{primary_node}")
        {:ok, %{dir: mnesia_dir, mode: :replica, primary_node: primary_node}}

      {:error, reason} ->
        Logger.error("[mnesia_bootstrap] Failed to join primary #{primary_node}: #{inspect(reason)}")
        {:stop, {:replica_join_failed, reason}}
    end
  end
end
