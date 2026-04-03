defmodule PkiCaPortalWeb.Plugs.RequireAuthTest do
  use PkiCaPortalWeb.ConnCase

  alias PkiCaPortal.SessionStore
  alias PkiCaPortalWeb.Plugs.RequireAuth

  setup do
    SessionStore.clear_all()
    :ok
  end

  defp create_test_session(opts \\ %{}) do
    SessionStore.create(%{
      user_id: opts[:user_id] || "user-1",
      username: opts[:username] || "admin",
      role: opts[:role] || "ca_admin",
      tenant_id: opts[:tenant_id] || "tenant-1",
      ip: opts[:ip] || "127.0.0.1",
      user_agent: opts[:user_agent] || "TestAgent/1.0",
      display_name: opts[:display_name] || "Admin User",
      email: opts[:email] || "admin@test.com",
      ca_instance_id: opts[:ca_instance_id]
    })
  end

  describe "valid session" do
    test "assigns current_user from ETS", %{conn: conn} do
      {:ok, session_id} = create_test_session()

      conn =
        conn
        |> Plug.Conn.put_req_header("user-agent", "TestAgent/1.0")
        |> init_test_session(%{session_id: session_id})
        |> RequireAuth.call([])

      refute conn.halted
      assert conn.assigns.current_user.username == "admin"
      assert conn.assigns.current_user.role == "ca_admin"
      assert conn.assigns.current_user.display_name == "Admin User"
      assert conn.assigns.session_id == session_id
    end

    test "touches session on access", %{conn: conn} do
      {:ok, session_id} = create_test_session()
      {:ok, before} = SessionStore.lookup(session_id)
      Process.sleep(10)

      conn
      |> Plug.Conn.put_req_header("user-agent", "TestAgent/1.0")
      |> init_test_session(%{session_id: session_id})
      |> RequireAuth.call([])

      {:ok, after_touch} = SessionStore.lookup(session_id)
      assert DateTime.compare(after_touch.last_active_at, before.last_active_at) == :gt
    end
  end

  describe "no session" do
    test "redirects to login when no session_id", %{conn: conn} do
      conn =
        conn
        |> init_test_session(%{})
        |> RequireAuth.call([])

      assert conn.halted
      assert redirected_to(conn) == "/login"
    end
  end

  describe "expired session" do
    test "redirects to login and deletes session", %{conn: conn} do
      prev = Application.get_env(:pki_ca_portal, :session_idle_timeout_ms)
      Application.put_env(:pki_ca_portal, :session_idle_timeout_ms, 0)

      {:ok, session_id} = create_test_session()
      Process.sleep(1)

      conn =
        conn
        |> Plug.Conn.put_req_header("user-agent", "TestAgent/1.0")
        |> init_test_session(%{session_id: session_id})
        |> fetch_flash()
        |> RequireAuth.call([])

      assert conn.halted
      assert redirected_to(conn) == "/login"
      assert {:error, :not_found} = SessionStore.lookup(session_id)

      if prev, do: Application.put_env(:pki_ca_portal, :session_idle_timeout_ms, prev),
        else: Application.delete_env(:pki_ca_portal, :session_idle_timeout_ms)
    end
  end

  describe "revoked session" do
    test "redirects to login for deleted session", %{conn: conn} do
      {:ok, session_id} = create_test_session()
      SessionStore.delete(session_id)

      conn =
        conn
        |> init_test_session(%{session_id: session_id})
        |> RequireAuth.call([])

      assert conn.halted
      assert redirected_to(conn) == "/login"
    end
  end

  describe "user-agent pinning" do
    test "kills session on user-agent mismatch", %{conn: conn} do
      {:ok, session_id} = create_test_session(%{user_agent: "OriginalBrowser/1.0"})

      conn =
        conn
        |> Plug.Conn.put_req_header("user-agent", "DifferentBrowser/2.0")
        |> init_test_session(%{session_id: session_id})
        |> RequireAuth.call([])

      assert conn.halted
      assert redirected_to(conn) == "/login"
      assert {:error, :not_found} = SessionStore.lookup(session_id)
    end

    test "allows matching user-agent", %{conn: conn} do
      {:ok, session_id} = create_test_session(%{user_agent: "TestAgent/1.0"})

      conn =
        conn
        |> Plug.Conn.put_req_header("user-agent", "TestAgent/1.0")
        |> init_test_session(%{session_id: session_id})
        |> RequireAuth.call([])

      refute conn.halted
    end
  end

  describe "IP pinning" do
    test "continues session on IP change (advisory)", %{conn: conn} do
      prev = Application.get_env(:pki_ca_portal, :session_ip_pinning)
      Application.put_env(:pki_ca_portal, :session_ip_pinning, true)

      {:ok, session_id} = create_test_session(%{ip: "10.0.0.1", user_agent: "TestAgent/1.0"})

      conn =
        conn
        |> Map.put(:remote_ip, {192, 168, 1, 1})
        |> Plug.Conn.put_req_header("user-agent", "TestAgent/1.0")
        |> init_test_session(%{session_id: session_id})
        |> RequireAuth.call([])

      refute conn.halted

      {:ok, sess} = SessionStore.lookup(session_id)
      assert sess.ip == "192.168.1.1"

      if prev, do: Application.put_env(:pki_ca_portal, :session_ip_pinning, prev),
        else: Application.delete_env(:pki_ca_portal, :session_ip_pinning)
    end

    test "skips IP check when pinning disabled", %{conn: conn} do
      prev = Application.get_env(:pki_ca_portal, :session_ip_pinning)
      Application.put_env(:pki_ca_portal, :session_ip_pinning, false)

      {:ok, session_id} = create_test_session(%{ip: "10.0.0.1", user_agent: "TestAgent/1.0"})

      conn =
        conn
        |> Map.put(:remote_ip, {192, 168, 1, 1})
        |> Plug.Conn.put_req_header("user-agent", "TestAgent/1.0")
        |> init_test_session(%{session_id: session_id})
        |> RequireAuth.call([])

      refute conn.halted

      {:ok, sess} = SessionStore.lookup(session_id)
      assert sess.ip == "10.0.0.1"

      if prev, do: Application.put_env(:pki_ca_portal, :session_ip_pinning, prev),
        else: Application.delete_env(:pki_ca_portal, :session_ip_pinning)
    end
  end
end
