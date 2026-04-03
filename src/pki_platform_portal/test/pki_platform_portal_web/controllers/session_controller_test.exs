defmodule PkiPlatformPortalWeb.SessionControllerTest do
  use PkiPlatformPortalWeb.ConnCase

  setup do
    PkiPlatformPortal.SessionStore.clear_all()
    :ok
  end

  describe "GET /login" do
    test "renders login form", %{conn: conn} do
      conn = get(conn, ~p"/login")
      assert html_response(conn, 200) =~ "Platform Admin"
      assert html_response(conn, 200) =~ "session[username]"
      assert html_response(conn, 200) =~ "session[password]"
    end
  end

  describe "POST /login" do
    test "sets session_id and creates ETS session on login", %{conn: conn} do
      conn =
        post(conn, ~p"/login", %{
          "session" => %{
            "username" => "admin",
            "password" => "admin"
          }
        })

      assert redirected_to(conn) == "/"

      # Verify session_id is set in cookie session
      session_id = get_session(conn, :session_id)
      assert is_binary(session_id)

      # Verify ETS session exists
      assert {:ok, session} = PkiPlatformPortal.SessionStore.lookup(session_id)
      assert session.username == "admin"

      # Verify current_user is NOT in cookie (slimmed)
      assert is_nil(get_session(conn, :current_user))
    end

    test "renders error with invalid credentials", %{conn: conn} do
      conn =
        post(conn, ~p"/login", %{
          "session" => %{
            "username" => "admin",
            "password" => "wrong"
          }
        })

      assert html_response(conn, 200) =~ "Invalid credentials"
    end

    test "renders error with wrong username", %{conn: conn} do
      conn =
        post(conn, ~p"/login", %{
          "session" => %{
            "username" => "notadmin",
            "password" => "admin"
          }
        })

      assert html_response(conn, 200) =~ "Invalid credentials"
    end
  end

  describe "DELETE /logout" do
    test "clears ETS session and cookie on logout", %{conn: conn} do
      # Login first to get a session
      conn =
        post(conn, ~p"/login", %{
          "session" => %{
            "username" => "admin",
            "password" => "admin"
          }
        })

      session_id = get_session(conn, :session_id)
      assert is_binary(session_id)

      # Now logout
      conn = recycle(conn) |> delete(~p"/logout")
      assert redirected_to(conn) == "/login"

      # ETS session should be deleted
      assert {:error, :not_found} = PkiPlatformPortal.SessionStore.lookup(session_id)
    end

    test "redirects to /login even when not logged in", %{conn: conn} do
      conn = delete(conn, ~p"/logout")
      assert redirected_to(conn) == "/login"
    end
  end
end
