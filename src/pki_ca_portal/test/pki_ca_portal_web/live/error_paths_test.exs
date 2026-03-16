defmodule PkiCaPortalWeb.ErrorPathsTest do
  @moduledoc """
  Tests for error branches in LiveView handle_event callbacks.

  Temporarily swaps the CA engine client to an error-returning mock
  to exercise the {:error, reason} branches. Verifies that the LiveView
  handles errors gracefully without crashing and preserves existing state.
  """
  use PkiCaPortalWeb.ConnCase

  import Phoenix.LiveViewTest

  @user %{did: "did:ssdid:admin1", role: "ca_admin", ca_instance_id: 1}

  setup %{conn: conn} do
    conn = init_test_session(conn, %{current_user: @user})
    original = Application.get_env(:pki_ca_portal, :ca_engine_client)

    on_exit(fn ->
      Application.put_env(:pki_ca_portal, :ca_engine_client, original)
    end)

    {:ok, conn: conn}
  end

  describe "CeremonyLive error path" do
    test "initiate_ceremony error does not crash and preserves state", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/ceremony")

      # Swap to error mock after mount
      Application.put_env(:pki_ca_portal, :ca_engine_client, PkiCaPortal.CaEngineClient.ErrorMock)

      html =
        view
        |> form("#initiate-ceremony-form form", %{
          algorithm: "ML-DSA-65",
          keystore_id: "1",
          threshold_k: "2",
          threshold_n: "3",
          domain_info: "test domain"
        })
        |> render_submit()

      # View is still alive and renders the ceremony page with existing data
      assert html =~ "Key Ceremony"
      assert html =~ "ML-DSA-65"
      # No ceremony status section should appear (error means no result)
      refute html =~ "ceremony-state"
    end
  end

  describe "UsersLive error paths" do
    test "create_user error does not crash and preserves user list", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/users")

      Application.put_env(:pki_ca_portal, :ca_engine_client, PkiCaPortal.CaEngineClient.ErrorMock)

      html =
        view
        |> form("#create-user-form form", %{
          did: "did:ssdid:fail",
          display_name: "Fail User",
          role: "ca_admin"
        })
        |> render_submit()

      # View still works, existing users preserved
      assert html =~ "User Management"
      assert html =~ "Admin One"
      assert html =~ "Key Manager One"
      # Failed user was not added
      refute html =~ "Fail User"
    end

    test "delete_user error does not crash and preserves user list", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/users")

      Application.put_env(:pki_ca_portal, :ca_engine_client, PkiCaPortal.CaEngineClient.ErrorMock)

      html =
        view
        |> element("#user-1 button", "Delete")
        |> render_click()

      # View still works, user was not removed
      assert html =~ "User Management"
      assert html =~ "Admin One"
    end
  end

  describe "KeystoresLive error path" do
    test "configure_keystore error does not crash and preserves list", %{conn: conn} do
      {:ok, view, html_before} = live(conn, "/keystores")

      initial_count = length(Regex.scan(~r/<tr id="keystore-/, html_before))

      Application.put_env(:pki_ca_portal, :ca_engine_client, PkiCaPortal.CaEngineClient.ErrorMock)

      html =
        view
        |> form("#configure-keystore-form form", %{type: "software"})
        |> render_submit()

      # View still works, no new keystore was added
      assert html =~ "Keystore Management"
      new_count = length(Regex.scan(~r/<tr id="keystore-/, html))
      assert new_count == initial_count
    end
  end
end
