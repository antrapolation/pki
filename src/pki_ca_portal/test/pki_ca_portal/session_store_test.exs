defmodule PkiCaPortal.SessionStoreTest do
  use ExUnit.Case, async: false

  alias PkiCaPortal.SessionStore

  setup do
    SessionStore.clear_all()
    :ok
  end

  describe "create/1" do
    test "creates a session and returns session_id" do
      {:ok, session_id} = SessionStore.create(%{
        user_id: "user-1",
        username: "admin",
        role: "ca_admin",
        tenant_id: "tenant-1",
        ip: "127.0.0.1",
        user_agent: "Mozilla/5.0"
      })

      assert is_binary(session_id)
      assert byte_size(session_id) > 20
    end

    test "created session can be looked up" do
      {:ok, session_id} = SessionStore.create(%{
        user_id: "user-1",
        username: "admin",
        role: "ca_admin",
        tenant_id: "tenant-1",
        ip: "127.0.0.1",
        user_agent: "Mozilla/5.0"
      })

      {:ok, session} = SessionStore.lookup(session_id)
      assert session.user_id == "user-1"
      assert session.username == "admin"
      assert session.role == "ca_admin"
      assert session.tenant_id == "tenant-1"
      assert session.ip == "127.0.0.1"
      assert session.user_agent == "Mozilla/5.0"
      assert %DateTime{} = session.created_at
      assert %DateTime{} = session.last_active_at
    end
  end

  describe "lookup/1" do
    test "returns error for nonexistent session" do
      assert {:error, :not_found} = SessionStore.lookup("nonexistent")
    end
  end

  describe "touch/1" do
    test "updates last_active_at" do
      {:ok, session_id} = SessionStore.create(%{
        user_id: "user-1", username: "admin", role: "ca_admin",
        tenant_id: "t1", ip: "127.0.0.1", user_agent: "Mozilla"
      })

      {:ok, before} = SessionStore.lookup(session_id)
      Process.sleep(10)
      :ok = SessionStore.touch(session_id)
      {:ok, after_touch} = SessionStore.lookup(session_id)

      assert DateTime.compare(after_touch.last_active_at, before.last_active_at) == :gt
    end
  end

  describe "update_ip/2" do
    test "updates the IP address" do
      {:ok, session_id} = SessionStore.create(%{
        user_id: "user-1", username: "admin", role: "ca_admin",
        tenant_id: "t1", ip: "127.0.0.1", user_agent: "Mozilla"
      })

      :ok = SessionStore.update_ip(session_id, "10.0.0.5")
      {:ok, session} = SessionStore.lookup(session_id)
      assert session.ip == "10.0.0.5"
    end
  end

  describe "delete/1" do
    test "removes the session" do
      {:ok, session_id} = SessionStore.create(%{
        user_id: "user-1", username: "admin", role: "ca_admin",
        tenant_id: "t1", ip: "127.0.0.1", user_agent: "Mozilla"
      })

      :ok = SessionStore.delete(session_id)
      assert {:error, :not_found} = SessionStore.lookup(session_id)
    end
  end

  describe "list_all/0" do
    test "returns all active sessions" do
      {:ok, _} = SessionStore.create(%{
        user_id: "user-1", username: "admin", role: "ca_admin",
        tenant_id: "t1", ip: "127.0.0.1", user_agent: "Mozilla"
      })
      {:ok, _} = SessionStore.create(%{
        user_id: "user-2", username: "km1", role: "key_manager",
        tenant_id: "t1", ip: "10.0.0.2", user_agent: "Chrome"
      })

      sessions = SessionStore.list_all()
      assert length(sessions) == 2
    end
  end

  describe "list_by_user/1" do
    test "returns sessions for a specific user" do
      {:ok, _} = SessionStore.create(%{
        user_id: "user-1", username: "admin", role: "ca_admin",
        tenant_id: "t1", ip: "127.0.0.1", user_agent: "Mozilla"
      })
      {:ok, _} = SessionStore.create(%{
        user_id: "user-2", username: "km1", role: "key_manager",
        tenant_id: "t1", ip: "10.0.0.2", user_agent: "Chrome"
      })

      sessions = SessionStore.list_by_user("user-1")
      assert length(sessions) == 1
      assert hd(sessions).username == "admin"
    end
  end

  describe "sweep/1" do
    test "removes sessions idle beyond timeout" do
      {:ok, session_id} = SessionStore.create(%{
        user_id: "user-1", username: "admin", role: "ca_admin",
        tenant_id: "t1", ip: "127.0.0.1", user_agent: "Mozilla"
      })

      Process.sleep(2)
      swept = SessionStore.sweep(0)
      assert swept >= 1
      assert {:error, :not_found} = SessionStore.lookup(session_id)
    end

    test "preserves sessions within timeout" do
      {:ok, session_id} = SessionStore.create(%{
        user_id: "user-1", username: "admin", role: "ca_admin",
        tenant_id: "t1", ip: "127.0.0.1", user_agent: "Mozilla"
      })

      swept = SessionStore.sweep(999_999_999)
      assert swept == 0
      assert {:ok, _} = SessionStore.lookup(session_id)
    end
  end

  describe "expired?/2" do
    test "returns true for sessions idle beyond timeout" do
      {:ok, session_id} = SessionStore.create(%{
        user_id: "user-1", username: "admin", role: "ca_admin",
        tenant_id: "t1", ip: "127.0.0.1", user_agent: "Mozilla"
      })

      Process.sleep(2)
      assert SessionStore.expired?(session_id, 0)
    end

    test "returns false for fresh sessions" do
      {:ok, session_id} = SessionStore.create(%{
        user_id: "user-1", username: "admin", role: "ca_admin",
        tenant_id: "t1", ip: "127.0.0.1", user_agent: "Mozilla"
      })

      refute SessionStore.expired?(session_id, 999_999_999)
    end
  end
end
