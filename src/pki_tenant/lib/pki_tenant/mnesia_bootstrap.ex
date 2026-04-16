defmodule PkiTenant.MnesiaBootstrap do
  @moduledoc """
  Opens or creates Mnesia tables on tenant boot.
  Uses MNESIA_DIR env var or /var/lib/pki/tenants/<slug>/mnesia/.
  """
  use GenServer

  require Logger

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(opts) do
    slug = Keyword.get(opts, :slug, "dev")
    mnesia_dir = System.get_env("MNESIA_DIR") || "/var/lib/pki/tenants/#{slug}/mnesia"

    File.mkdir_p!(mnesia_dir)
    Application.put_env(:mnesia, :dir, String.to_charlist(mnesia_dir))

    :mnesia.stop()
    :mnesia.create_schema([node()])
    :ok = :mnesia.start()
    :ok = PkiMnesia.Schema.create_tables()

    table_names = :mnesia.system_info(:local_tables) -- [:schema]
    :mnesia.wait_for_tables(table_names, 10_000)

    Logger.info("[mnesia_bootstrap] Mnesia started at #{mnesia_dir} with #{length(table_names)} tables")

    {:ok, %{dir: mnesia_dir}}
  end
end
