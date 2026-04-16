defmodule PkiTenant.HealthTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.TestHelper
  alias PkiTenant.Health

  setup do
    dir = TestHelper.setup_mnesia()
    on_exit(fn -> TestHelper.teardown_mnesia(dir) end)
    :ok
  end

  test "check returns status :ok with mnesia running" do
    result = Health.check()
    assert result.status == :ok
    assert result.mnesia == :running
    assert result.node == node()
    assert is_integer(result.uptime_seconds)
    assert is_integer(result.memory_mb)
  end
end
