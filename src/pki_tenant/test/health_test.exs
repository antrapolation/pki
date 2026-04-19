defmodule PkiTenant.HealthTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.TestHelper
  alias PkiTenant.Health

  setup do
    dir = TestHelper.setup_mnesia()
    on_exit(fn -> TestHelper.teardown_mnesia(dir) end)
    :ok
  end

  test "check/0 returns all expected keys" do
    result = Health.check()

    assert Map.has_key?(result, :status)
    assert Map.has_key?(result, :mnesia)
    assert Map.has_key?(result, :tables)
    assert Map.has_key?(result, :active_keys)
    assert Map.has_key?(result, :last_backup)
    assert Map.has_key?(result, :uptime_seconds)
  end

  test "check/0 returns healthy status when mnesia is running" do
    result = Health.check()
    assert result.status == "healthy"
    assert result.mnesia == "running"
  end

  test "check/0 returns tables as integer" do
    result = Health.check()
    assert is_integer(result.tables)
    assert result.tables > 0
  end

  test "check/0 returns active_keys as integer" do
    result = Health.check()
    assert is_integer(result.active_keys)
  end

  test "check/0 returns last_backup as nil when no backups exist" do
    result = Health.check()
    assert result.last_backup == nil
  end

  test "check/0 returns last_backup as DateTime when backup record exists" do
    alias PkiMnesia.Structs.BackupRecord
    alias PkiMnesia.Repo

    record = BackupRecord.new(%{type: "local", status: "completed"})
    {:ok, _} = Repo.insert(record)

    result = Health.check()
    assert %DateTime{} = result.last_backup
  end

  test "check/0 returns uptime_seconds as positive integer" do
    result = Health.check()
    assert is_integer(result.uptime_seconds)
    assert result.uptime_seconds >= 0
  end
end
