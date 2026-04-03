defmodule PkiPlatformEngine.DateLogHandler do
  @moduledoc """
  Custom Logger handler that writes logs to daily ISO-date-named files.

  Files: logs/pki/YYYY-MM-DD.log
  Retention: configurable, default 7 days
  Cleanup: runs on startup and at midnight rotation

  Started once from the platform engine (shared dependency).
  All apps in the BEAM node write to the same file. Use the `portal`
  metadata field to filter by app when searching logs.
  """

  use GenServer
  require Logger

  @default_retention_days 7

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(opts) do
    log_dir = opts[:log_dir] || "logs"
    app_name = opts[:app_name] || "pki"
    retention_days = opts[:retention_days] || @default_retention_days

    dir = Path.join(log_dir, app_name)
    File.mkdir_p!(dir)

    today = Date.utc_today()
    file_path = file_path_for(dir, today)
    {:ok, fd} = File.open(file_path, [:append, :utf8])

    cleanup_old_files(dir, retention_days)

    # Schedule rotation at midnight instead of polling
    schedule_midnight_rotation()

    # Register as Erlang logger handler
    handler_id = :pki_date_log

    :logger.add_handler(handler_id, __MODULE__, %{
      config: %{server: __MODULE__}
    })

    {:ok,
     %{
       dir: dir,
       app_name: app_name,
       retention_days: retention_days,
       current_date: today,
       fd: fd,
       file_path: file_path,
       handler_id: handler_id
     }}
  end

  # --- Erlang :logger handler callbacks ---

  def adding_handler(config), do: {:ok, config}
  def removing_handler(_config), do: :ok

  def log(%{level: level, msg: msg, meta: meta}, %{config: %{server: server}}) do
    formatted = format_log(level, msg, meta)
    GenServer.cast(server, {:write, formatted})
  end

  def changing_config(_action, _old_config, new_config), do: {:ok, new_config}

  # --- GenServer callbacks ---

  @impl true
  def handle_cast({:write, line}, state) do
    today = Date.utc_today()

    state =
      if today != state.current_date do
        rotate(state, today)
      else
        state
      end

    IO.write(state.fd, line)
    {:noreply, state}
  end

  @impl true
  def handle_info(:rotate, state) do
    today = Date.utc_today()

    state =
      if today != state.current_date do
        rotate(state, today)
      else
        state
      end

    schedule_midnight_rotation()
    {:noreply, state}
  end

  @impl true
  def terminate(_reason, state) do
    :logger.remove_handler(state.handler_id)
    File.close(state.fd)
    :ok
  rescue
    _ -> :ok
  end

  # --- Private ---

  defp rotate(state, new_date) do
    File.close(state.fd)
    cleanup_old_files(state.dir, state.retention_days)

    new_path = file_path_for(state.dir, new_date)
    {:ok, new_fd} = File.open(new_path, [:append, :utf8])

    %{state | current_date: new_date, fd: new_fd, file_path: new_path}
  end

  defp schedule_midnight_rotation do
    now = DateTime.utc_now()
    tomorrow = Date.utc_today() |> Date.add(1)
    midnight = DateTime.new!(tomorrow, ~T[00:00:00], "Etc/UTC")
    ms = max(DateTime.diff(midnight, now, :millisecond) + 1000, 1000)
    Process.send_after(self(), :rotate, ms)
  end

  defp cleanup_old_files(dir, retention_days) do
    cutoff = Date.utc_today() |> Date.add(-retention_days)

    dir
    |> File.ls!()
    |> Enum.filter(&String.ends_with?(&1, ".log"))
    |> Enum.each(fn filename ->
      case Date.from_iso8601(String.replace_suffix(filename, ".log", "")) do
        {:ok, file_date} ->
          if Date.compare(file_date, cutoff) == :lt do
            File.rm(Path.join(dir, filename))
          end

        _ ->
          :ok
      end
    end)
  rescue
    _ -> :ok
  end

  defp file_path_for(dir, date) do
    Path.join(dir, "#{Date.to_iso8601(date)}.log")
  end

  defp format_log(level, msg, meta) do
    timestamp = format_timestamp(meta[:time])
    message = format_message(msg)

    meta_parts =
      [:request_id, :user_id, :username, :tenant_id, :portal, :session_id]
      |> Enum.map(fn key ->
        case Map.get(meta, key) do
          nil -> nil
          val -> "#{key}=#{val}"
        end
      end)
      |> Enum.reject(&is_nil/1)
      |> Enum.join(" ")

    meta_str = if meta_parts == "", do: "", else: " #{meta_parts}"

    "#{timestamp} [#{level}]#{meta_str} #{message}\n"
  end

  defp format_timestamp(nil), do: DateTime.utc_now() |> DateTime.to_iso8601()

  defp format_timestamp(microseconds) when is_integer(microseconds) do
    microseconds
    |> DateTime.from_unix!(:microsecond)
    |> DateTime.to_iso8601()
  end

  defp format_message({:string, msg}), do: IO.iodata_to_binary(msg)
  defp format_message({:report, report}), do: inspect(report)
  defp format_message(msg) when is_binary(msg), do: msg
  defp format_message(msg), do: inspect(msg)
end
