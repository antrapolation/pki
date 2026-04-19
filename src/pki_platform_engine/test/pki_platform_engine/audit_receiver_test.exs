defmodule PkiPlatformEngine.AuditReceiverTest do
  use ExUnit.Case, async: false

  alias PkiPlatformEngine.AuditReceiver

  setup do
    if pid = Process.whereis(AuditReceiver) do
      GenServer.stop(pid)
    end

    {:ok, pid} = AuditReceiver.start_link()
    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)
    :ok
  end

  test "receives audit events without crashing" do
    GenServer.cast(AuditReceiver, {:audit_event, %{action: "test", tenant_id: "t1", timestamp: DateTime.utc_now()}})
    Process.sleep(50)
    assert Process.alive?(Process.whereis(AuditReceiver))
  end

  test "receives tenant_ready without crashing" do
    GenServer.cast(AuditReceiver, {:tenant_ready, "t1"})
    Process.sleep(50)
    assert Process.alive?(Process.whereis(AuditReceiver))
  end
end
