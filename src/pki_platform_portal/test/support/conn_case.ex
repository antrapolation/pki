defmodule PkiPlatformPortalWeb.ConnCase do
  @moduledoc """
  This module defines the test case to be used by
  tests that require setting up a connection.
  """

  use ExUnit.CaseTemplate

  using do
    quote do
      @endpoint PkiPlatformPortalWeb.Endpoint

      use PkiPlatformPortalWeb, :verified_routes

      import Plug.Conn
      import Phoenix.ConnTest
      import PkiPlatformPortalWeb.ConnCase
    end
  end

  setup tags do
    alias Ecto.Adapters.SQL.Sandbox
    alias PkiPlatformEngine.PlatformRepo

    :ok = Sandbox.checkout(PlatformRepo)
    unless tags[:async], do: Sandbox.mode(PlatformRepo, {:shared, self()})

    {:ok, conn: Phoenix.ConnTest.build_conn()}
  end

  @doc """
  Seeds a super_admin user (so `RequireSetup` stops redirecting to
  `/setup`), creates a server-side session in `SessionStore`, and
  puts the `session_id` in the plug session on `conn`. Returns the
  updated conn plus the seeded user + session_id.

  Intended for LiveView tests of routes behind the auth pipeline.
  """
  def log_in_as_super_admin(conn, opts \\ []) do
    alias PkiPlatformEngine.{PlatformRepo, UserProfile}

    attrs = %{
      username: Keyword.get(opts, :username, "testadmin"),
      display_name: Keyword.get(opts, :display_name, "Test Admin"),
      email: Keyword.get(opts, :email, "admin@test.local"),
      password: Keyword.get(opts, :password, "Passw0rd!"),
      global_role: "super_admin",
      status: "active"
    }

    {:ok, user} =
      %UserProfile{}
      |> UserProfile.registration_changeset(attrs)
      |> PlatformRepo.insert()

    {:ok, session_id} =
      PkiPlatformPortal.SessionStore.create(%{
        user_id: user.id,
        username: user.username,
        role: "super_admin",
        tenant_id: nil,
        ip: "127.0.0.1",
        user_agent: "ExUnit/Test",
        display_name: user.display_name,
        email: user.email
      })

    conn =
      conn
      |> Plug.Conn.put_req_header("user-agent", "ExUnit/Test")
      |> Plug.Test.init_test_session(%{session_id: session_id})

    %{conn: conn, user: user, session_id: session_id}
  end
end
