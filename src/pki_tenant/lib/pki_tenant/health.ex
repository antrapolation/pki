defmodule PkiTenant.Health do
  @moduledoc """
  Health check module called by platform via :erpc.call.
  Returns a detailed health map with status, Mnesia state, active keys,
  last backup timestamp, and uptime.
  """

  alias PkiMnesia.Repo
  alias PkiMnesia.Structs.BackupRecord

  def check do
    mnesia = mnesia_status()
    tables = mnesia_table_count()
    active_keys = active_key_count()
    last_backup = latest_backup_at()
    uptime = uptime_seconds()

    status =
      if mnesia == "running", do: "healthy", else: "degraded"

    %{
      status: status,
      mnesia: mnesia,
      tables: tables,
      active_keys: active_keys,
      last_backup: last_backup,
      uptime_seconds: uptime
    }
  end

  # -- Private helpers --

  defp mnesia_status do
    case :mnesia.system_info(:is_running) do
      :yes -> "running"
      _ -> "stopped"
    end
  rescue
    _ -> "stopped"
  end

  defp mnesia_table_count do
    case :mnesia.system_info(:is_running) do
      :yes ->
        :mnesia.system_info(:tables) |> length()
      _ ->
        0
    end
  rescue
    _ -> 0
  end

  defp active_key_count do
    case Process.whereis(PkiCaEngine.KeyActivation) do
      nil -> 0
      _pid -> PkiCaEngine.KeyActivation.count_active()
    end
  rescue
    _ -> 0
  end

  defp latest_backup_at do
    case Repo.all(BackupRecord) do
      {:ok, []} ->
        nil

      {:ok, records} ->
        records
        |> Enum.filter(fn r -> r.status == "completed" end)
        |> Enum.max_by(fn r -> DateTime.to_unix(r.inserted_at) end, fn -> nil end)
        |> case do
          nil -> nil
          record -> record.inserted_at
        end

      _ ->
        nil
    end
  rescue
    _ -> nil
  end

  defp uptime_seconds do
    :erlang.statistics(:wall_clock) |> elem(0) |> div(1000)
  end
end
