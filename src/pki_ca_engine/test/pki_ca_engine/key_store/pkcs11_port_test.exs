defmodule PkiCaEngine.KeyStore.Pkcs11PortTest do
  use ExUnit.Case, async: false

  alias PkiCaEngine.KeyStore.Pkcs11Port

  @stub_port Path.expand("../../support/fake_pkcs11_port.py", __DIR__)

  @tag :requires_python
  describe "request-ID correlation" do
    test "ping discards stale responses and returns :pong" do
      pid =
        start_supervised!(
          {Pkcs11Port,
           [
             port_binary: @stub_port,
             library_path: "/fake/lib.so",
             slot_id: 0,
             pin: "1234"
           ]}
        )

      # The stub sends {"error":"stale","id":999} then {"ok":true,"id":N} for ping.
      # New code (await_response with ID matching) must discard the stale and return :pong.
      assert {:ok, :pong} = Pkcs11Port.ping(pid)
    end

    test "consecutive pings each get their own correct response" do
      pid =
        start_supervised!(
          {Pkcs11Port,
           [
             port_binary: @stub_port,
             library_path: "/fake/lib.so",
             slot_id: 0,
             pin: "1234"
           ]}
        )

      assert {:ok, :pong} = Pkcs11Port.ping(pid)
      assert {:ok, :pong} = Pkcs11Port.ping(pid)
      assert {:ok, :pong} = Pkcs11Port.ping(pid)
    end
  end
end
