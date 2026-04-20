defmodule PkiPlatformPortalWeb.TenantNewLiveTest do
  @moduledoc """
  Handler-level LiveView tests for the New Tenant wizard.

  The async provisioning chain (register → spawn → admin → activate)
  is exercised end-to-end under `test/integration/` with a real
  `:peer`-spawned BEAM. These tests cover the handler logic that
  sits in front of that chain:

    * Initial render / field affordances
    * `validate` event — inline field errors via phx-change
    * `submit` event — client-side validation gate before Task.async
    * Login gate at the /login redirect

  They deliberately stop short of asserting on the Task lifecycle —
  the wizard's next step (`:start_register_step`) kicks off a real
  Task that talks to the platform DB, which would make these tests
  slow and coupled.
  """
  use PkiPlatformPortalWeb.ConnCase

  import Phoenix.LiveViewTest

  alias PkiPlatformEngine.{PlatformRepo, Tenant}

  setup %{conn: conn} do
    PkiPlatformPortal.SessionStore.clear_all()
    %{conn: conn} = log_in_as_super_admin(conn)
    {:ok, conn: conn}
  end

  describe "initial render" do
    test "mounts with empty form fields", %{conn: conn} do
      {:ok, view, html} = live(conn, "/tenants/new")

      assert html =~ "New Tenant"
      # form renders in the :form phase with name/slug/email inputs
      assert has_element?(view, ~s|input[name="name"]|)
      assert has_element?(view, ~s|input[name="slug"]|)
      assert has_element?(view, ~s|input[name="email"]|)
    end
  end

  describe "validate event (phx-change)" do
    test "flags an invalid slug format", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/tenants/new")

      html =
        view
        |> form("#tenant-form", %{"name" => "Acme Co", "slug" => "BAD SLUG!", "email" => "ok@x.test"})
        |> render_change()

      assert html =~ "Slug must contain only lowercase"
    end

    test "flags an invalid email", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/tenants/new")

      html =
        view
        |> form("#tenant-form", %{"name" => "Acme Co", "slug" => "acme-co", "email" => "not-an-email"})
        |> render_change()

      assert html =~ "valid email"
    end

    test "clears errors when fields become valid", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/tenants/new")

      # Trip the error first.
      bad_html =
        view
        |> form("#tenant-form", %{"name" => "", "slug" => "BAD", "email" => "x"})
        |> render_change()

      assert bad_html =~ "Slug must contain only lowercase"

      # Then fix them.
      good_html =
        view
        |> form("#tenant-form", %{"name" => "Acme Co", "slug" => "acme-co", "email" => "ok@example.test"})
        |> render_change()

      refute good_html =~ "Slug must contain only lowercase"
      refute good_html =~ "valid email"
    end

    test "flags a slug that collides with an existing tenant", %{conn: conn} do
      %Tenant{}
      |> Tenant.changeset(%{
        name: "Prior",
        slug: "duplicate-slug",
        email: "prior@example.test",
        schema_mode: "beam",
        status: "active"
      })
      |> PlatformRepo.insert!()

      {:ok, view, _html} = live(conn, "/tenants/new")

      html =
        view
        |> form("#tenant-form", %{"name" => "New", "slug" => "duplicate-slug", "email" => "new@example.test"})
        |> render_change()

      assert html =~ "tenant with that slug already exists"
    end
  end

  describe "submit event" do
    test "invalid input keeps the form in :form phase with an error", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/tenants/new")

      html =
        view
        |> form("#tenant-form", %{"name" => "", "slug" => "", "email" => ""})
        |> render_submit()

      # Still showing the form — no wizard progress bar yet.
      assert has_element?(view, ~s|input[name="name"]|)
      assert html =~ "required"
    end
  end

  test "redirects to /login when unauthenticated" do
    conn = Phoenix.ConnTest.build_conn() |> Plug.Test.init_test_session(%{})
    assert {:error, {:redirect, %{to: "/login"}}} = live(conn, "/tenants/new")
  end
end
