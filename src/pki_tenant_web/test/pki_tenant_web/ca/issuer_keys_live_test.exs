defmodule PkiTenantWeb.Ca.IssuerKeysLiveTest do
  use PkiTenantWeb.LiveCase, async: false

  describe "IssuerKeysLive — lifecycle transitions" do
    test "suspend_key transitions an active key to suspended", %{conn: conn} do
      key = seed_issuer_key(%{status: "active"})

      {:ok, view, _html} = live(conn, "/issuer-keys")
      render_click(view, "suspend_key", %{"id" => key.id})

      {:ok, updated} = Repo.get(IssuerKey, key.id)
      assert updated.status == "suspended"
    end

    test "reactivate_key transitions a suspended key back to active", %{conn: conn} do
      key = seed_issuer_key(%{status: "suspended"})

      {:ok, view, _html} = live(conn, "/issuer-keys")
      render_click(view, "reactivate_key", %{"id" => key.id})

      {:ok, updated} = Repo.get(IssuerKey, key.id)
      assert updated.status == "active"
    end

    test "retire_key transitions an active key to retired (ca_admin)", %{conn: conn} do
      key = seed_issuer_key(%{status: "active"})

      {:ok, view, _html} = live(conn, "/issuer-keys")
      render_click(view, "retire_key", %{"id" => key.id})

      {:ok, updated} = Repo.get(IssuerKey, key.id)
      assert updated.status == "retired"
    end

    test "retire_key transitions a suspended key to retired (key_manager allowed)" do
      conn = build_conn_for_role(:key_manager)
      key = seed_issuer_key(%{status: "suspended"})

      {:ok, view, _html} = live(conn, "/issuer-keys")
      render_click(view, "retire_key", %{"id" => key.id})

      {:ok, updated} = Repo.get(IssuerKey, key.id)
      assert updated.status == "retired"
    end

    test "archive_key transitions a retired key to archived (ca_admin)", %{conn: conn} do
      key = seed_issuer_key(%{status: "retired"})

      {:ok, view, _html} = live(conn, "/issuer-keys")
      render_click(view, "archive_key", %{"id" => key.id})

      {:ok, updated} = Repo.get(IssuerKey, key.id)
      assert updated.status == "archived"
    end

    test "retire_key is blocked for auditor role — key status unchanged" do
      conn = build_conn_for_role(:auditor)
      key = seed_issuer_key(%{status: "active"})

      # Auditor is redirected away — cannot mount the page at all.
      assert {:error, {:redirect, _}} = live(conn, "/issuer-keys")

      {:ok, unchanged} = Repo.get(IssuerKey, key.id)
      assert unchanged.status == "active"
    end

    test "archive_key is blocked for key_manager role — key status unchanged" do
      conn = build_conn_for_role(:key_manager)
      key = seed_issuer_key(%{status: "retired"})

      {:ok, view, _html} = live(conn, "/issuer-keys")
      render_click(view, "archive_key", %{"id" => key.id})

      {:ok, unchanged} = Repo.get(IssuerKey, key.id)
      assert unchanged.status == "retired"
    end

    test "suspend_key returns error flash for unknown key id", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/issuer-keys")
      html = render_click(view, "suspend_key", %{"id" => "nonexistent-key-id"})
      assert html =~ "Failed to suspend"
    end

    test "invalid transition returns error flash", %{conn: conn} do
      # Archived key cannot be suspended — transition_status returns error.
      key = seed_issuer_key(%{status: "archived"})

      {:ok, view, _html} = live(conn, "/issuer-keys")
      html = render_click(view, "suspend_key", %{"id" => key.id})

      assert html =~ "Failed to suspend"
      {:ok, unchanged} = Repo.get(IssuerKey, key.id)
      assert unchanged.status == "archived"
    end
  end

  describe "IssuerKeysLive — mount" do
    test "mounts successfully with empty issuer key list", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/issuer-keys")
      assert html =~ "Issuer Keys"
    end

    test "auditor is redirected away from issuer-keys page" do
      conn = build_conn_for_role(:auditor)
      assert {:error, {:redirect, _}} = live(conn, "/issuer-keys")
    end
  end
end
