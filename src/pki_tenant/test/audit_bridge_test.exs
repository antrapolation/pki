defmodule PkiTenant.AuditBridgeTest do
  use ExUnit.Case, async: false

  alias PkiTenant.AuditBridge

  setup do
    {:ok, pid} = AuditBridge.start_link(tenant_id: "test-tenant", platform_node: nil)
    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)
    %{pid: pid}
  end

  test "log/2 does not crash when platform_node is nil" do
    # Should buffer locally without error
    AuditBridge.log("test_action", %{detail: "hello"})
    Process.sleep(50)
    assert Process.alive?(Process.whereis(AuditBridge))
  end

  test "log/1 works with default empty attrs" do
    AuditBridge.log("simple_action")
    Process.sleep(50)
    assert Process.alive?(Process.whereis(AuditBridge))
  end
end
