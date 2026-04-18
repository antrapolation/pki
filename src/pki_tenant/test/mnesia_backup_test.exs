defmodule PkiTenant.MnesiaBackupTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.TestHelper
  alias PkiMnesia.Repo
  alias PkiMnesia.Structs.BackupRecord
  alias PkiTenant.MnesiaBackup

  setup do
    dir = TestHelper.setup_mnesia()
    backup_dir = Path.join(dir, "backups")
    File.mkdir_p!(backup_dir)
    on_exit(fn -> TestHelper.teardown_mnesia(dir) end)
    {:ok, backup_dir: backup_dir}
  end

  describe "last_backup_time/0" do
    test "returns nil when no backup has been performed", %{backup_dir: backup_dir} do
      {:ok, pid} = MnesiaBackup.start_link(
        name: :"test_backup_#{:erlang.unique_integer([:positive])}",
        backup_dir: backup_dir,
        start_timer: false
      )

      assert MnesiaBackup.last_backup_time(pid) == nil
    end
  end

  describe "backup_now/1" do
    test "local backup writes a BackupRecord to Mnesia", %{backup_dir: backup_dir} do
      {:ok, pid} = MnesiaBackup.start_link(
        name: :"test_backup_#{:erlang.unique_integer([:positive])}",
        backup_dir: backup_dir,
        start_timer: false
      )

      {:ok, _path} = MnesiaBackup.backup_now(pid)

      {:ok, records} = Repo.all(BackupRecord)
      local_records = Enum.filter(records, fn r -> r.type == "local" end)
      assert length(local_records) >= 1

      record = hd(local_records)
      assert record.status == "completed"
      assert record.size_bytes > 0
      assert String.contains?(record.location, "mnesia-")
    end

    test "backup_now updates last_backup_time", %{backup_dir: backup_dir} do
      {:ok, pid} = MnesiaBackup.start_link(
        name: :"test_backup_#{:erlang.unique_integer([:positive])}",
        backup_dir: backup_dir,
        start_timer: false
      )

      assert MnesiaBackup.last_backup_time(pid) == nil

      {:ok, _path} = MnesiaBackup.backup_now(pid)

      assert %DateTime{} = MnesiaBackup.last_backup_time(pid)
    end
  end

  describe "upload_now/1 — S3 not configured" do
    test "returns {:error, :s3_not_configured} when no bucket configured", %{backup_dir: backup_dir} do
      {:ok, pid} = MnesiaBackup.start_link(
        name: :"test_backup_#{:erlang.unique_integer([:positive])}",
        backup_dir: backup_dir,
        start_timer: false,
        s3_bucket: nil,
        s3_access_key: nil,
        s3_secret_key: nil
      )

      # Create a local backup first so there is something to upload
      {:ok, _path} = MnesiaBackup.backup_now(pid)

      result = MnesiaBackup.upload_now(pid)
      assert result == {:error, :s3_not_configured}
    end

    test "returns {:error, :no_backups} when backup dir is empty", %{backup_dir: backup_dir} do
      empty_dir = Path.join(backup_dir, "empty_sub_#{:erlang.unique_integer([:positive])}")
      File.mkdir_p!(empty_dir)

      {:ok, pid} = MnesiaBackup.start_link(
        name: :"test_backup_#{:erlang.unique_integer([:positive])}",
        backup_dir: empty_dir,
        start_timer: false
      )

      result = MnesiaBackup.upload_now(pid)
      assert result == {:error, :no_backups}
    end
  end
end
