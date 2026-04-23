defmodule PkiPlatformEngine.AuditReceiverTest do
  use ExUnit.Case, async: false

  alias PkiPlatformEngine.AuditReceiver

  setup do
    # Start a private, non-global AuditReceiver. Do NOT stop the
    # globally-registered one: it's a child of the app's
    # :rest_for_one supervisor with :permanent restart, so stopping
    # it races the supervisor's restart and eventually crashes the
    # entire supervision tree (taking PlatformRepo with it).
    name = :"test_audit_receiver_#{System.unique_integer([:positive])}"
    {:ok, pid} = AuditReceiver.start_link(name: name)
    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)
    {:ok, receiver: name}
  end

  test "receives audit events without crashing", %{receiver: r} do
    GenServer.cast(r, {:audit_event, %{action: "test", tenant_id: "t1", timestamp: DateTime.utc_now()}})
    Process.sleep(50)
    assert Process.alive?(Process.whereis(r))
  end

  test "receives tenant_ready without crashing", %{receiver: r} do
    GenServer.cast(r, {:tenant_ready, "t1"})
    Process.sleep(50)
    assert Process.alive?(Process.whereis(r))
  end
end
