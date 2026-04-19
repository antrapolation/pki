defmodule PkiTenant.MnesiaBackup do
  @moduledoc "Periodic Mnesia backup with optional daily S3 upload."
  use GenServer
  require Logger

  # ---------------------------------------------------------------------------
  # Public API
  # ---------------------------------------------------------------------------

  def start_link(opts) do
    name = opts[:name] || __MODULE__
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  def backup_now(server \\ __MODULE__) do
    GenServer.call(server, :backup_now, 30_000)
  end

  def last_backup_time(server \\ __MODULE__) do
    GenServer.call(server, :last_backup_time)
  end

  def upload_now(server \\ __MODULE__) do
    GenServer.call(server, :upload_now, 60_000)
  end

  # ---------------------------------------------------------------------------
  # GenServer callbacks
  # ---------------------------------------------------------------------------

  def init(opts) do
    interval = opts[:interval_ms] || 3_600_000  # 1 hour default
    backup_dir = opts[:backup_dir] || Path.join(System.get_env("MNESIA_DIR", "/tmp/mnesia"), "backups")
    File.mkdir_p!(backup_dir)
    max_backups = opts[:max_backups] || 24

    s3_config = %{
      bucket: opts[:s3_bucket] || System.get_env("BACKUP_S3_BUCKET"),
      endpoint: opts[:s3_endpoint] || System.get_env("BACKUP_S3_ENDPOINT", "https://s3.amazonaws.com"),
      access_key: opts[:s3_access_key] || System.get_env("BACKUP_S3_ACCESS_KEY"),
      secret_key: opts[:s3_secret_key] || System.get_env("BACKUP_S3_SECRET_KEY"),
      region: opts[:s3_region] || System.get_env("BACKUP_S3_REGION", "us-east-1")
    }

    age_recipient = opts[:age_recipient] || System.get_env("BACKUP_AGE_RECIPIENT")
    upload_interval = opts[:upload_interval_ms] || 86_400_000  # 24 hours

    if opts[:start_timer] != false do
      Process.send_after(self(), :scheduled_backup, interval)

      if s3_config.bucket do
        Process.send_after(self(), :scheduled_upload, upload_interval)
      end
    end

    {:ok, %{
      interval: interval,
      backup_dir: backup_dir,
      max_backups: max_backups,
      last_backup_at: nil,
      s3_config: s3_config,
      age_recipient: age_recipient,
      upload_interval: upload_interval
    }}
  end

  def handle_call(:backup_now, _from, state) do
    case do_backup(state.backup_dir, state.max_backups) do
      {:ok, path} ->
        {:reply, {:ok, path}, %{state | last_backup_at: DateTime.utc_now()}}

      error ->
        {:reply, error, state}
    end
  end

  def handle_call(:last_backup_time, _from, state) do
    {:reply, state.last_backup_at, state}
  end

  def handle_call(:upload_now, _from, state) do
    result = do_daily_upload(state)
    {:reply, result, state}
  end

  def handle_info(:scheduled_backup, state) do
    state =
      case do_backup(state.backup_dir, state.max_backups) do
        {:ok, _path} -> %{state | last_backup_at: DateTime.utc_now()}
        _error -> state
      end

    Process.send_after(self(), :scheduled_backup, state.interval)
    {:noreply, state}
  end

  def handle_info(:scheduled_upload, state) do
    do_daily_upload(state)
    Process.send_after(self(), :scheduled_upload, state.upload_interval)
    {:noreply, state}
  end

  # ---------------------------------------------------------------------------
  # Private — local backup
  # ---------------------------------------------------------------------------

  defp do_backup(backup_dir, max_backups) do
    timestamp = DateTime.utc_now() |> DateTime.to_iso8601() |> String.replace(~r/[:\.]/, "-")
    path = Path.join(backup_dir, "mnesia-#{timestamp}.bak")

    case :mnesia.backup(String.to_charlist(path)) do
      :ok ->
        Logger.info("Mnesia backup created: #{path}")
        prune_old_backups(backup_dir, max_backups)
        size = File.stat!(path).size
        record_backup(:local, size, path)
        {:ok, path}

      {:error, reason} ->
        Logger.error("Mnesia backup failed: #{inspect(reason)}")
        record_backup_failure(:local, reason)
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

  # ---------------------------------------------------------------------------
  # Private — S3 upload
  # ---------------------------------------------------------------------------

  defp do_daily_upload(state) do
    with {:ok, latest_path} <- find_latest_backup(state.backup_dir),
         {:ok, data} <- encrypt_backup(latest_path, state.age_recipient),
         :ok <- upload_to_s3(latest_path, data, state.s3_config) do
      record_backup(:remote, byte_size(data), s3_location(latest_path, state.s3_config))
      {:ok, latest_path}
    else
      {:error, :no_backups} ->
        Logger.warning("[backup] No local backups found for upload")
        {:error, :no_backups}

      {:error, :s3_not_configured} ->
        Logger.info("[backup] S3 not configured, skipping upload")
        {:error, :s3_not_configured}

      {:error, reason} ->
        Logger.error("[backup] Daily upload failed: #{inspect(reason)}")
        record_backup_failure(:remote, reason)
        {:error, reason}
    end
  end

  defp find_latest_backup(dir) do
    case dir
         |> File.ls!()
         |> Enum.filter(&String.starts_with?(&1, "mnesia-"))
         |> Enum.sort()
         |> List.last() do
      nil -> {:error, :no_backups}
      file -> {:ok, Path.join(dir, file)}
    end
  end

  defp encrypt_backup(path, nil) do
    # No age recipient configured — upload unencrypted
    File.read(path)
  end

  defp encrypt_backup(path, recipient) do
    case System.cmd("age", ["-r", recipient, "-o", "-", path], stderr_to_stdout: true) do
      {output, 0} -> {:ok, output}
      {error, _} -> {:error, {:age_encrypt_failed, error}}
    end
  rescue
    e -> {:error, {:age_not_available, Exception.message(e)}}
  end

  defp upload_to_s3(_path, _data, %{bucket: nil}), do: {:error, :s3_not_configured}
  defp upload_to_s3(_path, _data, %{access_key: nil}), do: {:error, :s3_not_configured}

  defp upload_to_s3(path, data, s3_config) do
    filename = Path.basename(path)
    # Node name gives us tenant slug, e.g., pki_tenant_comp5@host -> comp5
    node_slug =
      node()
      |> to_string()
      |> String.split("@")
      |> hd()
      |> String.replace("pki_tenant_", "")

    s3_key = "tenant-#{node_slug}/#{filename}.age"

    PkiTenant.S3Upload.put_object(s3_config.bucket, s3_key, data, %{
      endpoint: s3_config.endpoint,
      access_key: s3_config.access_key,
      secret_key: s3_config.secret_key,
      region: s3_config.region
    })
  end

  defp s3_location(path, s3_config) do
    filename = Path.basename(path)

    node_slug =
      node()
      |> to_string()
      |> String.split("@")
      |> hd()
      |> String.replace("pki_tenant_", "")

    "s3://#{s3_config.bucket}/tenant-#{node_slug}/#{filename}.age"
  end

  # ---------------------------------------------------------------------------
  # Private — BackupRecord persistence
  # ---------------------------------------------------------------------------

  defp record_backup(type, size_bytes, location) do
    alias PkiMnesia.Structs.BackupRecord

    record = BackupRecord.new(%{
      type: to_string(type),
      size_bytes: size_bytes,
      location: location,
      status: "completed"
    })

    PkiMnesia.Repo.insert(record)
  rescue
    _ -> :ok
  end

  defp record_backup_failure(type, reason) do
    alias PkiMnesia.Structs.BackupRecord

    record = BackupRecord.new(%{
      type: to_string(type),
      status: "failed",
      error: inspect(reason)
    })

    PkiMnesia.Repo.insert(record)
  rescue
    _ -> :ok
  end
end
