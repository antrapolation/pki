defmodule PkiPlatformPortalWeb.TenantsLiveTest do
  use PkiPlatformPortalWeb.ConnCase

  import Phoenix.LiveViewTest

  alias PkiPlatformEngine.{PlatformRepo, Tenant}

  setup %{conn: conn} do
    PkiPlatformPortal.SessionStore.clear_all()
    %{conn: conn} = log_in_as_super_admin(conn)
    {:ok, conn: conn}
  end

  defp insert_tenant(attrs) do
    defaults = %{
      name: "Acme #{System.unique_integer([:positive])}",
      slug: "acme#{System.unique_integer([:positive])}",
      email: "owner@example.test",
      status: "active",
      schema_mode: "beam"
    }

    %Tenant{}
    |> Tenant.changeset(Map.merge(defaults, attrs))
    |> PlatformRepo.insert!()
  end

  describe "initial render" do
    test "mounts /tenants and shows the header", %{conn: conn} do
      {:ok, view, html} = live(conn, "/tenants")

      assert html =~ "Tenants"
      assert has_element?(view, "#tenants-page")
      assert has_element?(view, "#tenant-list")
    end

    test "shows empty state when no tenants exist", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/tenants")
      assert render(view) =~ "No tenants yet"
    end

    test "renders 'New Tenant' link pointing to /tenants/new", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/tenants")
      assert html =~ ~s(href="/tenants/new")
    end
  end

  describe "with tenants present" do
    setup do
      active = insert_tenant(%{name: "Active Co", slug: "active-co", status: "active"})
      suspended = insert_tenant(%{name: "Suspended Co", slug: "suspended-co", status: "suspended"})
      failed = insert_tenant(%{name: "Failed Co", slug: "failed-co", status: "failed"})
      %{active: active, suspended: suspended, failed: failed}
    end

    test "renders each tenant's row with its slug + status badge", %{conn: conn, active: a, suspended: s, failed: f} do
      {:ok, view, _html} = live(conn, "/tenants")

      assert has_element?(view, "#tenant-#{a.id}")
      assert has_element?(view, "#tenant-#{s.id}")
      assert has_element?(view, "#tenant-#{f.id}")

      html = render(view)
      assert html =~ a.slug
      assert html =~ s.slug
      assert html =~ f.slug
    end

    test "shows the resume button for failed and provisioning rows", %{conn: conn, failed: f, active: a} do
      {:ok, view, _html} = live(conn, "/tenants")

      # Failed → resume button visible, activate hidden
      assert has_element?(view, ~s|#tenant-#{f.id} button[phx-click="resume_provisioning"]|)
      refute has_element?(view, ~s|#tenant-#{a.id} button[phx-click="resume_provisioning"]|)
    end

    test "shows the delete button only for non-active rows", %{conn: conn, active: a, suspended: s} do
      {:ok, view, _html} = live(conn, "/tenants")

      refute has_element?(view, ~s|#tenant-#{a.id} button[phx-click="delete_tenant"]|)
      assert has_element?(view, ~s|#tenant-#{s.id} button[phx-click="delete_tenant"]|)
    end

    test "delete event blocks active tenants with a flash error", %{conn: conn, active: a} do
      {:ok, view, _html} = live(conn, "/tenants")

      render_hook(view, "delete_tenant", %{"id" => a.id})

      # Row should still be present (not deleted) and the flash text
      # that the handler emits should now appear in the DOM.
      assert has_element?(view, "#tenant-#{a.id}")
      assert render(view) =~ "Active tenants must be suspended"
    end

    test "page counter reflects total", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/tenants")
      # initial html is pre-load_data — re-render to pick up the count
      assert render(view) =~ "3 total"
    end
  end

  describe "pagination" do
    setup do
      # Seed 12 tenants so the default 10-per-page list paginates.
      Enum.each(1..12, fn i ->
        insert_tenant(%{name: "Tenant #{i}", slug: "tenant-page-#{i}", status: "active"})
      end)

      :ok
    end

    test "change_page event moves to a valid page", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/tenants")
      assert render(view) =~ "12 total"

      render_hook(view, "change_page", %{"page" => "2"})
      # On page 2 the pagination strip shows "2" in btn-active
      assert render(view) =~ ~r|btn-active">2|
    end

    test "change_page ignores junk input", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/tenants")
      assert render(view) =~ "12 total"

      render_hook(view, "change_page", %{"page" => "not_a_number"})
      # Still on page 1
      assert render(view) =~ ~r|btn-active">1|
    end
  end

  test "redirects to /login when unauthenticated" do
    # Build a naked conn without logging in.
    conn = Phoenix.ConnTest.build_conn() |> Plug.Test.init_test_session(%{})
    assert {:error, {:redirect, %{to: "/login"}}} = live(conn, "/tenants")
  end
end
