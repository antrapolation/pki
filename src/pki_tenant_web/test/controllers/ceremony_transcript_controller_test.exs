defmodule PkiTenantWeb.Ca.CeremonyTranscriptControllerTest do
  @moduledoc """
  Exercises the plain-HTML print endpoint end-to-end: session gate,
  Mnesia lookup, layout-free render, signature blocks.
  """
  use PkiTenantWeb.ConnCase, async: false

  alias PkiCaEngine.CeremonyOrchestrator
  alias PkiMnesia.TestHelper
  alias PkiTenantWeb.SessionStore

  setup do
    dir = TestHelper.setup_mnesia()
    on_exit(fn -> TestHelper.teardown_mnesia(dir) end)
    :ok
  end

  defp make_session(conn, role \\ "ca_admin") do
    case SessionStore.start_link([]) do
      {:ok, _} -> :ok
      {:error, {:already_started, _}} -> :ok
    end

    {:ok, session_id} =
      SessionStore.create(%{
        user_id: "user-1",
        username: "admin",
        display_name: "Admin",
        role: role,
        ip: "127.0.0.1",
        user_agent: "test-agent",
        portal: :ca
      })

    conn
    |> Plug.Test.init_test_session(%{})
    |> Plug.Conn.put_session(:session_id, session_id)
  end

  defp seed_ceremony do
    {:ok, {ceremony, _key, _shares, _participants, _transcript}} =
      CeremonyOrchestrator.initiate("ca-transcript-test", %{
        algorithm: "ECC-P256",
        threshold_k: 2,
        threshold_n: 3,
        custodian_names: ["Custodian 1", "Custodian 2", "Custodian 3"],
        auditor_name: "External Auditor",
        is_root: true,
        ceremony_mode: :full,
        initiated_by: "Admin",
        key_alias: "transcript-test",
        subject_dn: "/CN=Transcript Test CA"
      })

    {:ok, _} = CeremonyOrchestrator.accept_share_by_slot(ceremony.id, 1, "Alice Johnson", "mypassw0rd99!")

    ceremony
  end

  describe "GET /ceremonies/:id/transcript" do
    test "redirects to /login when no session", %{conn: conn} do
      ceremony = seed_ceremony()

      conn =
        conn
        |> Plug.Test.init_test_session(%{})
        |> Phoenix.ConnTest.dispatch(PkiTenantWeb.CaRouter, :get, "/ceremonies/#{ceremony.id}/transcript")

      assert redirected_to(conn) == "/login"
    end

    test "renders full ceremony transcript for authenticated user", %{conn: conn} do
      ceremony = seed_ceremony()

      conn =
        conn
        |> make_session()
        |> Phoenix.ConnTest.dispatch(PkiTenantWeb.CaRouter, :get, "/ceremonies/#{ceremony.id}/transcript")

      assert html_response(conn, 200) =~ "Key Ceremony Transcript"
      body = html_response(conn, 200)

      # Ceremony metadata rendered
      assert body =~ ceremony.id
      assert body =~ "ECC-P256"
      assert body =~ "2-of-3"
      assert body =~ "External Auditor"

      # Accepted custodian's real name is in a signature block
      assert body =~ "Alice Johnson"

      # Custodian 2 + 3 are still pending — placeholders visible
      assert body =~ "— awaiting entry —"

      # Print button hint visible on screen (hidden by @media print)
      assert body =~ "Print this page"
    end

    test "returns 404 for unknown ceremony id", %{conn: conn} do
      conn =
        conn
        |> make_session()
        |> Phoenix.ConnTest.dispatch(PkiTenantWeb.CaRouter, :get, "/ceremonies/nonexistent-ceremony-id/transcript")

      assert response(conn, 404) =~ "not found"
    end
  end
end

# End of module

