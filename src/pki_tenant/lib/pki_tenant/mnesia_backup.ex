defmodule PkiTenant.MnesiaBackup do
  @moduledoc "Periodic Mnesia backup for tenant data."
  use GenServer
  require Logger

  def start_link(opts) do
    name = opts[:name] || __MODULE__
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  def backup_now(server \\ __MODULE__) do
    GenServer.call(server, :backup_now, 30_000)
  end

  def init(opts) do
    interval = opts[:interval_ms] || 3_600_000  # 1 hour default
    backup_dir = opts[:backup_dir] || Path.join(System.get_env("MNESIA_DIR", "/tmp/mnesia"), "backups")
    File.mkdir_p!(backup_dir)
    max_backups = opts[:max_backups] || 24

    if opts[:start_timer] != false do
      Process.send_after(self(), :scheduled_backup, interval)
    end

    {:ok, %{interval: interval, backup_dir: backup_dir, max_backups: max_backups}}
  end

  def handle_call(:backup_now, _from, state) do
    result = do_backup(state.backup_dir, state.max_backups)
    {:reply, result, state}
  end

  def handle_info(:scheduled_backup, state) do
    do_backup(state.backup_dir, state.max_backups)
    Process.send_after(self(), :scheduled_backup, state.interval)
    {:noreply, state}
  end

  defp do_backup(backup_dir, max_backups) do
    timestamp = DateTime.utc_now() |> DateTime.to_iso8601() |> String.replace(~r/[:\.]/, "-")
    path = Path.join(backup_dir, "mnesia-#{timestamp}.bak")

    case :mnesia.backup(String.to_charlist(path)) do
      :ok ->
        Logger.info("Mnesia backup created: #{path}")
        prune_old_backups(backup_dir, max_backups)
        {:ok, path}
      {:error, reason} ->
        Logger.error("Mnesia backup failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp prune_old_backups(dir, max) do
    dir
    |> File.ls!()
    |> Enum.filter(&String.starts_with?(&1, "mnesia-"))
    |> Enum.sort()
    |> Enum.reverse()
    |> Enum.drop(max)
    |> Enum.each(fn file -> File.rm(Path.join(dir, file)) end)
  end
end
