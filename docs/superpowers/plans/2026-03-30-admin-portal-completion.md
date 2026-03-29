# Admin Portal Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the Platform Admin Portal with bootstrap setup, tenant health metrics, system monitoring, platform admin management, RA engine multi-tenancy, and tenant-aware CA/RA setup pages.

**Architecture:** Database-backed admin auth replaces env-var auth. RA engine gets `tenant_id` column for multi-tenancy. Platform engine gets new modules for admin management, health checks, and tenant metrics. CA/RA portal setup pages accept `?tenant=slug` for tenant-scoped admin creation.

**Tech Stack:** Elixir/Phoenix LiveView, Ecto, PostgreSQL, Tailwind CSS + DaisyUI, Argon2 for password hashing, Req for HTTP health checks.

---

## File Map

### New Files

| File | Responsibility |
|------|---------------|
| `src/pki_platform_engine/priv/platform_repo/migrations/20260330000001_create_platform_admins.exs` | Migration for platform_admins table |
| `src/pki_platform_engine/lib/pki_platform_engine/platform_admin.ex` | Ecto schema for platform admin users |
| `src/pki_platform_engine/lib/pki_platform_engine/admin_management.ex` | Context: CRUD, auth, constraints for platform admins |
| `src/pki_platform_engine/lib/pki_platform_engine/tenant_metrics.ex` | Queries tenant DBs for health metrics |
| `src/pki_platform_engine/lib/pki_platform_engine/system_health.ex` | Polls service /health endpoints |
| `src/pki_platform_portal/lib/pki_platform_portal_web/live/setup_live.ex` | Bootstrap: first super admin creation |
| `src/pki_platform_portal/lib/pki_platform_portal_web/live/tenant_new_live.ex` | Create tenant form page |
| `src/pki_platform_portal/lib/pki_platform_portal_web/live/tenant_detail_live.ex` | Tenant detail with health metrics & status |
| `src/pki_platform_portal/lib/pki_platform_portal_web/live/system_live.ex` | System monitoring dashboard |
| `src/pki_platform_portal/lib/pki_platform_portal_web/live/admins_live.ex` | Platform admin user management |
| `src/pki_platform_portal/lib/pki_platform_portal_web/plugs/require_setup.ex` | Plug: redirects to /setup if no admins exist |
| `src/pki_ra_engine/priv/repo/migrations/20260330000001_add_tenant_id_to_ra_users.exs` | Migration: add tenant_id to ra_users |

### Modified Files

| File | Changes |
|------|---------|
| `src/pki_platform_portal/lib/pki_platform_portal_web/router.ex` | Add routes for setup, tenant detail, system, admins |
| `src/pki_platform_portal/lib/pki_platform_portal_web/components/layouts.ex` | Add System and Admins to sidebar |
| `src/pki_platform_portal/lib/pki_platform_portal_web/controllers/session_controller.ex` | DB-backed auth via AdminManagement |
| `src/pki_platform_portal/lib/pki_platform_portal_web/live/tenants_live.ex` | Remove inline form, add New Tenant button |
| `src/pki_platform_portal/lib/pki_platform_portal_web/live/dashboard_live.ex` | Add setup status summary |
| `src/pki_ra_engine/lib/pki_ra_engine/schema/ra_user.ex` | Add tenant_id field |
| `src/pki_ra_engine/lib/pki_ra_engine/user_management.ex` | Filter by tenant_id |
| `src/pki_ra_engine/lib/pki_ra_engine/api/user_controller.ex` | Accept tenant_id param |
| `src/pki_ca_portal/lib/pki_ca_portal_web/controllers/setup_controller.ex` | Accept ?tenant=slug |
| `src/pki_ra_portal/lib/pki_ra_portal_web/controllers/setup_controller.ex` | Accept ?tenant=slug |

---

### Task 1: Platform Admin Schema & Migration

**Files:**
- Create: `src/pki_platform_engine/priv/platform_repo/migrations/20260330000001_create_platform_admins.exs`
- Create: `src/pki_platform_engine/lib/pki_platform_engine/platform_admin.ex`

- [ ] **Step 1: Create the migration**

```elixir
# src/pki_platform_engine/priv/platform_repo/migrations/20260330000001_create_platform_admins.exs
defmodule PkiPlatformEngine.PlatformRepo.Migrations.CreatePlatformAdmins do
  use Ecto.Migration

  def change do
    create table(:platform_admins, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :username, :string, null: false
      add :password_hash, :string, null: false
      add :display_name, :string, null: false
      add :role, :string, null: false, default: "super_admin"
      add :status, :string, null: false, default: "active"

      timestamps()
    end

    create unique_index(:platform_admins, [:username])
  end
end
```

- [ ] **Step 2: Create the schema module**

```elixir
# src/pki_platform_engine/lib/pki_platform_engine/platform_admin.ex
defmodule PkiPlatformEngine.PlatformAdmin do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "platform_admins" do
    field :username, :string
    field :password_hash, :string
    field :password, :string, virtual: true
    field :display_name, :string
    field :role, :string, default: "super_admin"
    field :status, :string, default: "active"

    timestamps()
  end

  def changeset(admin, attrs) do
    admin
    |> cast(attrs, [:username, :display_name, :status])
    |> validate_required([:username, :display_name])
    |> unique_constraint(:username)
    |> validate_inclusion(:status, ["active", "suspended"])
  end

  def registration_changeset(admin, attrs) do
    admin
    |> cast(attrs, [:username, :display_name, :password])
    |> validate_required([:username, :display_name, :password])
    |> validate_length(:password, min: 8)
    |> unique_constraint(:username)
    |> hash_password()
  end

  defp hash_password(%{valid?: true, changes: %{password: password}} = changeset) do
    put_change(changeset, :password_hash, Argon2.hash_pwd_salt(password))
  end

  defp hash_password(changeset), do: changeset
end
```

- [ ] **Step 3: Run migration**

Run: `cd src/pki_platform_engine && MIX_ENV=dev mix ecto.migrate`
Expected: Migration creates `platform_admins` table

- [ ] **Step 4: Commit**

```bash
git add src/pki_platform_engine/priv/platform_repo/migrations/20260330000001_create_platform_admins.exs src/pki_platform_engine/lib/pki_platform_engine/platform_admin.ex
git commit -m "feat: add platform_admins schema and migration"
```

---

### Task 2: Admin Management Context

**Files:**
- Create: `src/pki_platform_engine/lib/pki_platform_engine/admin_management.ex`

- [ ] **Step 1: Create the admin management module**

```elixir
# src/pki_platform_engine/lib/pki_platform_engine/admin_management.ex
defmodule PkiPlatformEngine.AdminManagement do
  alias PkiPlatformEngine.PlatformRepo
  alias PkiPlatformEngine.PlatformAdmin

  import Ecto.Query

  def needs_setup? do
    PlatformRepo.aggregate(PlatformAdmin, :count) == 0
  end

  def register_admin(attrs) do
    %PlatformAdmin{}
    |> PlatformAdmin.registration_changeset(attrs)
    |> PlatformRepo.insert()
  end

  def authenticate(username, password) do
    admin =
      PlatformRepo.one(
        from(a in PlatformAdmin,
          where: a.username == ^username and a.status == "active"
        )
      )

    case admin do
      nil -> {:error, :invalid_credentials}
      admin ->
        if Argon2.verify_pass(password, admin.password_hash) do
          {:ok, admin}
        else
          {:error, :invalid_credentials}
        end
    end
  end

  def list_admins do
    PlatformRepo.all(from(a in PlatformAdmin, order_by: [asc: a.inserted_at]))
  end

  def get_admin(id) do
    PlatformRepo.get(PlatformAdmin, id)
  end

  def update_admin(%PlatformAdmin{} = admin, attrs) do
    admin
    |> PlatformAdmin.changeset(attrs)
    |> PlatformRepo.update()
  end

  def suspend_admin(%PlatformAdmin{} = admin) do
    active_count =
      PlatformRepo.aggregate(
        from(a in PlatformAdmin, where: a.status == "active"),
        :count
      )

    if active_count <= 1 do
      {:error, :last_active_admin}
    else
      update_admin(admin, %{status: "suspended"})
    end
  end

  def activate_admin(%PlatformAdmin{} = admin) do
    update_admin(admin, %{status: "active"})
  end

  def delete_admin(%PlatformAdmin{} = admin) do
    active_count =
      PlatformRepo.aggregate(
        from(a in PlatformAdmin, where: a.status == "active"),
        :count
      )

    if active_count <= 1 and admin.status == "active" do
      {:error, :last_active_admin}
    else
      PlatformRepo.delete(admin)
    end
  end

  def seed_from_env do
    username = Application.get_env(:pki_platform_portal, :admin_username)
    password = Application.get_env(:pki_platform_portal, :admin_password)

    if username && password && needs_setup?() do
      case register_admin(%{
             username: username,
             display_name: "Platform Admin",
             password: password
           }) do
        {:ok, _admin} ->
          require Logger
          Logger.warning("Seeded platform admin from env vars. This is deprecated — manage admins via the portal.")
        {:error, _} -> :ok
      end
    end
  end
end
```

- [ ] **Step 2: Commit**

```bash
git add src/pki_platform_engine/lib/pki_platform_engine/admin_management.ex
git commit -m "feat: add AdminManagement context for platform admin CRUD and auth"
```

---

### Task 3: Bootstrap Setup Page

**Files:**
- Create: `src/pki_platform_portal/lib/pki_platform_portal_web/live/setup_live.ex`
- Create: `src/pki_platform_portal/lib/pki_platform_portal_web/plugs/require_setup.ex`
- Modify: `src/pki_platform_portal/lib/pki_platform_portal_web/router.ex`

- [ ] **Step 1: Create the RequireSetup plug**

```elixir
# src/pki_platform_portal/lib/pki_platform_portal_web/plugs/require_setup.ex
defmodule PkiPlatformPortalWeb.Plugs.RequireSetup do
  import Plug.Conn
  import Phoenix.Controller

  def init(opts), do: opts

  def call(conn, _opts) do
    if PkiPlatformEngine.AdminManagement.needs_setup?() do
      conn
      |> redirect(to: "/setup")
      |> halt()
    else
      conn
    end
  end
end
```

- [ ] **Step 2: Create SetupLive**

```elixir
# src/pki_platform_portal/lib/pki_platform_portal_web/live/setup_live.ex
defmodule PkiPlatformPortalWeb.SetupLive do
  use PkiPlatformPortalWeb, :live_view

  @impl true
  def mount(_params, _session, socket) do
    if PkiPlatformEngine.AdminManagement.needs_setup?() do
      {:ok,
       assign(socket,
         page_title: "Initial Setup",
         form_error: nil
       ), layout: false}
    else
      {:ok, push_navigate(socket, to: "/login")}
    end
  end

  @impl true
  def handle_event("create_admin", params, socket) do
    %{"username" => username, "display_name" => display_name, "password" => password, "password_confirmation" => confirmation} = params

    cond do
      String.length(password) < 8 ->
        {:noreply, assign(socket, form_error: "Password must be at least 8 characters.")}

      password != confirmation ->
        {:noreply, assign(socket, form_error: "Passwords do not match.")}

      true ->
        case PkiPlatformEngine.AdminManagement.register_admin(%{
               username: username,
               display_name: display_name,
               password: password
             }) do
          {:ok, _admin} ->
            {:noreply, push_navigate(socket, to: "/login")}

          {:error, changeset} ->
            error =
              Ecto.Changeset.traverse_errors(changeset, fn {msg, _} -> msg end)
              |> Enum.map(fn {k, v} -> "#{k}: #{Enum.join(v, ", ")}" end)
              |> Enum.join("; ")

            {:noreply, assign(socket, form_error: error)}
        end
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="min-h-screen flex items-center justify-center bg-base-200 p-4">
      <div class="card bg-base-100 shadow-lg w-full max-w-md">
        <div class="card-body">
          <div class="flex items-center gap-3 mb-4">
            <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-primary">
              <.icon name="hero-server-stack" class="size-5 text-primary-content" />
            </div>
            <div>
              <h1 class="text-lg font-bold">Platform Setup</h1>
              <p class="text-xs text-base-content/50">Create the first administrator account</p>
            </div>
          </div>

          <%= if @form_error do %>
            <div class="alert alert-error text-sm mb-3">
              <.icon name="hero-exclamation-circle" class="size-4" />
              <span>{@form_error}</span>
            </div>
          <% end %>

          <form phx-submit="create_admin" class="space-y-4">
            <div>
              <label class="block text-sm font-medium mb-1">Username</label>
              <input type="text" name="username" required class="input input-bordered w-full" placeholder="admin" autocomplete="username" />
            </div>
            <div>
              <label class="block text-sm font-medium mb-1">Display Name</label>
              <input type="text" name="display_name" required class="input input-bordered w-full" placeholder="Platform Admin" />
            </div>
            <div>
              <label class="block text-sm font-medium mb-1">Password</label>
              <input type="password" name="password" required minlength="8" class="input input-bordered w-full" autocomplete="new-password" />
            </div>
            <div>
              <label class="block text-sm font-medium mb-1">Confirm Password</label>
              <input type="password" name="password_confirmation" required minlength="8" class="input input-bordered w-full" autocomplete="new-password" />
            </div>
            <button type="submit" class="btn btn-primary w-full" phx-disable-with="Creating account...">
              Create Admin Account
            </button>
          </form>
        </div>
      </div>
    </div>
    """
  end
end
```

- [ ] **Step 3: Update the router**

Replace the entire router file:

```elixir
# src/pki_platform_portal/lib/pki_platform_portal_web/router.ex
defmodule PkiPlatformPortalWeb.Router do
  use PkiPlatformPortalWeb, :router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {PkiPlatformPortalWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
  end

  pipeline :require_auth do
    plug PkiPlatformPortalWeb.Plugs.RequireSetup
    plug PkiPlatformPortalWeb.Plugs.RequireAuth
  end

  pipeline :api do
    plug :accepts, ["json"]
  end

  # Setup route (no auth, no setup check)
  scope "/", PkiPlatformPortalWeb do
    pipe_through :browser

    live "/setup", SetupLive
    get "/login", SessionController, :new
    post "/login", SessionController, :create
    delete "/logout", SessionController, :delete
  end

  # Protected routes
  scope "/", PkiPlatformPortalWeb do
    pipe_through [:browser, :require_auth]

    live_session :authenticated, on_mount: PkiPlatformPortalWeb.Live.AuthHook do
      live "/", DashboardLive
      live "/tenants", TenantsLive
      live "/tenants/new", TenantNewLive
      live "/tenants/:id", TenantDetailLive
      live "/system", SystemLive
      live "/admins", AdminsLive
    end
  end
end
```

- [ ] **Step 4: Update SessionController to use DB auth**

Replace `src/pki_platform_portal/lib/pki_platform_portal_web/controllers/session_controller.ex`:

```elixir
defmodule PkiPlatformPortalWeb.SessionController do
  use PkiPlatformPortalWeb, :controller

  def new(conn, _params) do
    render(conn, :login, layout: false, error: nil)
  end

  def create(conn, %{"username" => username, "password" => password}) do
    case PkiPlatformEngine.AdminManagement.authenticate(username, password) do
      {:ok, admin} ->
        conn
        |> put_session(:current_user, %{
          id: admin.id,
          username: admin.username,
          display_name: admin.display_name,
          role: admin.role
        })
        |> redirect(to: "/")

      {:error, _} ->
        render(conn, :login, layout: false, error: "Invalid credentials")
    end
  end

  def delete(conn, _params) do
    conn
    |> clear_session()
    |> redirect(to: "/login")
  end
end
```

- [ ] **Step 5: Commit**

```bash
git add src/pki_platform_portal/lib/pki_platform_portal_web/live/setup_live.ex \
        src/pki_platform_portal/lib/pki_platform_portal_web/plugs/require_setup.ex \
        src/pki_platform_portal/lib/pki_platform_portal_web/router.ex \
        src/pki_platform_portal/lib/pki_platform_portal_web/controllers/session_controller.ex
git commit -m "feat: add bootstrap setup page and DB-backed admin auth"
```

---

### Task 4: Update Sidebar Navigation & Layouts

**Files:**
- Modify: `src/pki_platform_portal/lib/pki_platform_portal_web/components/layouts.ex`

- [ ] **Step 1: Add System and Admins links to sidebar**

In `layouts.ex`, find the `<nav>` section (around line 41-44) and replace:

```elixir
        <%!-- Navigation --%>
        <nav class="flex-1 px-2 py-3 space-y-0.5 overflow-y-auto">
          <.sidebar_link href="/" icon="hero-home" label="Dashboard" current={@page_title} />
          <.sidebar_link href="/tenants" icon="hero-building-office-2" label="Tenants" current={@page_title} />
          <.sidebar_link href="/system" icon="hero-server-stack" label="System" current={@page_title} />
          <.sidebar_link href="/admins" icon="hero-users" label="Admins" current={@page_title} />
        </nav>
```

- [ ] **Step 2: Update `is_active?/2` to handle new pages**

Replace the existing `is_active?` function clauses:

```elixir
  defp is_active?("Dashboard", "Dashboard"), do: true
  defp is_active?("Tenants", page) when page in ["Tenants", "New Tenant", "Tenant Detail"], do: true
  defp is_active?("System", "System"), do: true
  defp is_active?("Admins", "Admins"), do: true
  defp is_active?(_, _), do: false
```

- [ ] **Step 3: Commit**

```bash
git add src/pki_platform_portal/lib/pki_platform_portal_web/components/layouts.ex
git commit -m "feat: add System and Admins to sidebar navigation"
```

---

### Task 5: Platform Admin Management Page

**Files:**
- Create: `src/pki_platform_portal/lib/pki_platform_portal_web/live/admins_live.ex`

- [ ] **Step 1: Create AdminsLive**

```elixir
# src/pki_platform_portal/lib/pki_platform_portal_web/live/admins_live.ex
defmodule PkiPlatformPortalWeb.AdminsLive do
  use PkiPlatformPortalWeb, :live_view

  alias PkiPlatformEngine.AdminManagement

  @impl true
  def mount(_params, session, socket) do
    current_user = session["current_user"] || socket.assigns[:current_user]

    {:ok,
     assign(socket,
       page_title: "Admins",
       admins: AdminManagement.list_admins(),
       current_admin_id: current_user[:id] || current_user["id"],
       form_error: nil,
       show_form: false
     )}
  end

  @impl true
  def handle_event("toggle_form", _params, socket) do
    {:noreply, assign(socket, show_form: !socket.assigns.show_form, form_error: nil)}
  end

  def handle_event("create_admin", params, socket) do
    %{"username" => username, "display_name" => display_name, "password" => password, "password_confirmation" => confirmation} = params

    cond do
      String.length(password) < 8 ->
        {:noreply, assign(socket, form_error: "Password must be at least 8 characters.")}

      password != confirmation ->
        {:noreply, assign(socket, form_error: "Passwords do not match.")}

      true ->
        case AdminManagement.register_admin(%{username: username, display_name: display_name, password: password}) do
          {:ok, _admin} ->
            {:noreply,
             socket
             |> assign(admins: AdminManagement.list_admins(), show_form: false, form_error: nil)
             |> put_flash(:info, "Admin \"#{username}\" created.")}

          {:error, changeset} ->
            error =
              Ecto.Changeset.traverse_errors(changeset, fn {msg, _} -> msg end)
              |> Enum.map(fn {k, v} -> "#{k}: #{Enum.join(v, ", ")}" end)
              |> Enum.join("; ")
            {:noreply, assign(socket, form_error: error)}
        end
    end
  end

  def handle_event("suspend_admin", %{"id" => id}, socket) do
    if id == socket.assigns.current_admin_id do
      {:noreply, put_flash(socket, :error, "Cannot suspend yourself.")}
    else
      admin = AdminManagement.get_admin(id)
      case AdminManagement.suspend_admin(admin) do
        {:ok, _} ->
          {:noreply, socket |> assign(admins: AdminManagement.list_admins()) |> put_flash(:info, "Admin suspended.")}
        {:error, :last_active_admin} ->
          {:noreply, put_flash(socket, :error, "Cannot suspend the last active admin.")}
        {:error, _} ->
          {:noreply, put_flash(socket, :error, "Failed to suspend admin.")}
      end
    end
  end

  def handle_event("activate_admin", %{"id" => id}, socket) do
    admin = AdminManagement.get_admin(id)
    case AdminManagement.activate_admin(admin) do
      {:ok, _} ->
        {:noreply, socket |> assign(admins: AdminManagement.list_admins()) |> put_flash(:info, "Admin activated.")}
      {:error, _} ->
        {:noreply, put_flash(socket, :error, "Failed to activate admin.")}
    end
  end

  def handle_event("delete_admin", %{"id" => id}, socket) do
    if id == socket.assigns.current_admin_id do
      {:noreply, put_flash(socket, :error, "Cannot delete yourself.")}
    else
      admin = AdminManagement.get_admin(id)
      case AdminManagement.delete_admin(admin) do
        {:ok, _} ->
          {:noreply, socket |> assign(admins: AdminManagement.list_admins()) |> put_flash(:info, "Admin deleted.")}
        {:error, :last_active_admin} ->
          {:noreply, put_flash(socket, :error, "Cannot delete the last active admin.")}
        {:error, _} ->
          {:noreply, put_flash(socket, :error, "Failed to delete admin.")}
      end
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div id="admins-page" class="space-y-6">
      <div class="flex items-center justify-between">
        <h2 class="text-sm font-semibold">Platform Administrators</h2>
        <button phx-click="toggle_form" class="btn btn-primary btn-sm">
          <.icon name={if @show_form, do: "hero-x-mark", else: "hero-plus"} class="size-4" />
          {if @show_form, do: "Cancel", else: "New Admin"}
        </button>
      </div>

      <%= if @show_form do %>
        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-5">
            <h3 class="text-sm font-semibold mb-3">Create New Admin</h3>

            <%= if @form_error do %>
              <div class="alert alert-error text-sm mb-3">
                <.icon name="hero-exclamation-circle" class="size-4" />
                <span>{@form_error}</span>
              </div>
            <% end %>

            <form phx-submit="create_admin" class="space-y-3">
              <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div>
                  <label class="block text-xs font-medium text-base-content/60 mb-1">Username</label>
                  <input type="text" name="username" required class="input input-bordered input-sm w-full" />
                </div>
                <div>
                  <label class="block text-xs font-medium text-base-content/60 mb-1">Display Name</label>
                  <input type="text" name="display_name" required class="input input-bordered input-sm w-full" />
                </div>
                <div>
                  <label class="block text-xs font-medium text-base-content/60 mb-1">Password</label>
                  <input type="password" name="password" required minlength="8" class="input input-bordered input-sm w-full" />
                </div>
                <div>
                  <label class="block text-xs font-medium text-base-content/60 mb-1">Confirm Password</label>
                  <input type="password" name="password_confirmation" required minlength="8" class="input input-bordered input-sm w-full" />
                </div>
              </div>
              <div class="flex justify-end">
                <button type="submit" class="btn btn-primary btn-sm" phx-disable-with="Creating...">Create Admin</button>
              </div>
            </form>
          </div>
        </div>
      <% end %>

      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-0">
          <div class="overflow-x-auto">
            <table class="table table-sm">
              <thead>
                <tr class="text-xs uppercase text-base-content/50">
                  <th>Username</th>
                  <th>Display Name</th>
                  <th>Role</th>
                  <th>Status</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                <tr :for={admin <- @admins} class="hover">
                  <td class="font-mono text-sm">{admin.username}</td>
                  <td>{admin.display_name}</td>
                  <td><span class="badge badge-sm badge-primary">{admin.role}</span></td>
                  <td>
                    <span class={["badge badge-sm", admin.status == "active" && "badge-success", admin.status == "suspended" && "badge-warning"]}>
                      {admin.status}
                    </span>
                  </td>
                  <td class="text-sm text-base-content/60">{Calendar.strftime(admin.inserted_at, "%Y-%m-%d")}</td>
                  <td>
                    <div class="flex gap-1">
                      <button
                        :if={admin.status == "active" && admin.id != @current_admin_id}
                        phx-click="suspend_admin" phx-value-id={admin.id}
                        data-confirm="Suspend this admin?"
                        class="btn btn-ghost btn-xs text-warning"
                      >Suspend</button>
                      <button
                        :if={admin.status == "suspended"}
                        phx-click="activate_admin" phx-value-id={admin.id}
                        class="btn btn-ghost btn-xs text-success"
                      >Activate</button>
                      <button
                        :if={admin.id != @current_admin_id}
                        phx-click="delete_admin" phx-value-id={admin.id}
                        data-confirm="Permanently delete this admin?"
                        class="btn btn-ghost btn-xs text-error"
                      >Delete</button>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
    """
  end
end
```

- [ ] **Step 2: Commit**

```bash
git add src/pki_platform_portal/lib/pki_platform_portal_web/live/admins_live.ex
git commit -m "feat: add platform admin management page"
```

---

### Task 6: System Health Module & Monitoring Page

**Files:**
- Create: `src/pki_platform_engine/lib/pki_platform_engine/system_health.ex`
- Create: `src/pki_platform_portal/lib/pki_platform_portal_web/live/system_live.ex`

- [ ] **Step 1: Create SystemHealth module**

```elixir
# src/pki_platform_engine/lib/pki_platform_engine/system_health.ex
defmodule PkiPlatformEngine.SystemHealth do
  @services [
    %{name: "CA Engine", url: "http://127.0.0.1:4001/health", port: 4001},
    %{name: "CA Portal", url: "http://127.0.0.1:4002/", port: 4002},
    %{name: "RA Engine", url: "http://127.0.0.1:4003/health", port: 4003},
    %{name: "RA Portal", url: "http://127.0.0.1:4004/", port: 4004},
    %{name: "Validation", url: "http://127.0.0.1:4005/health", port: 4005},
    %{name: "Platform Portal", url: nil, port: 4006}
  ]

  def services, do: @services

  def check_all do
    Enum.map(@services, fn service ->
      Map.merge(service, check_service(service))
    end)
  end

  def check_service(%{url: nil}) do
    %{status: :healthy, response_time_ms: 0, checked_at: DateTime.utc_now()}
  end

  def check_service(%{url: url}) do
    start = System.monotonic_time(:millisecond)

    result =
      try do
        case Req.get(url, connect_options: [timeout: 3_000], receive_timeout: 3_000) do
          {:ok, %{status: status}} when status in 200..399 ->
            :healthy

          _ ->
            :unreachable
        end
      rescue
        _ -> :unreachable
      end

    elapsed = System.monotonic_time(:millisecond) - start

    %{status: result, response_time_ms: elapsed, checked_at: DateTime.utc_now()}
  end

  def check_database do
    try do
      Ecto.Adapters.SQL.query!(PkiPlatformEngine.PlatformRepo, "SELECT 1")
      %{status: :healthy}
    rescue
      _ -> %{status: :unreachable}
    end
  end

  def database_count do
    case Ecto.Adapters.SQL.query(PkiPlatformEngine.PlatformRepo, "SELECT count(*) FROM pg_database WHERE datname LIKE 'pki_%'") do
      {:ok, %{rows: [[count]]}} -> count
      _ -> 0
    end
  end
end
```

- [ ] **Step 2: Create SystemLive**

```elixir
# src/pki_platform_portal/lib/pki_platform_portal_web/live/system_live.ex
defmodule PkiPlatformPortalWeb.SystemLive do
  use PkiPlatformPortalWeb, :live_view

  alias PkiPlatformEngine.SystemHealth

  @poll_interval 30_000

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: Process.send_after(self(), :poll, @poll_interval)

    {:ok,
     assign(socket,
       page_title: "System",
       services: SystemHealth.check_all(),
       db_status: SystemHealth.check_database(),
       db_count: SystemHealth.database_count()
     )}
  end

  @impl true
  def handle_info(:poll, socket) do
    Process.send_after(self(), :poll, @poll_interval)

    {:noreply,
     assign(socket,
       services: SystemHealth.check_all(),
       db_status: SystemHealth.check_database(),
       db_count: SystemHealth.database_count()
     )}
  end

  @impl true
  def handle_event("refresh", _params, socket) do
    {:noreply,
     assign(socket,
       services: SystemHealth.check_all(),
       db_status: SystemHealth.check_database(),
       db_count: SystemHealth.database_count()
     )}
  end

  @impl true
  def render(assigns) do
    healthy_count = Enum.count(assigns.services, &(&1.status == :healthy))
    total_count = length(assigns.services)

    assigns =
      assigns
      |> assign(:healthy_count, healthy_count)
      |> assign(:total_count, total_count)

    ~H"""
    <div id="system-page" class="space-y-6">
      <div class="flex items-center justify-between">
        <h2 class="text-sm font-semibold">System Health</h2>
        <button phx-click="refresh" class="btn btn-ghost btn-sm" phx-disable-with="Checking...">
          <.icon name="hero-arrow-path" class="size-4" />
          Refresh
        </button>
      </div>

      <%!-- Summary --%>
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-5">
            <div class="flex items-center gap-3">
              <div class={["flex items-center justify-center w-10 h-10 rounded-lg", if(@healthy_count == @total_count, do: "bg-success/10", else: "bg-warning/10")]}>
                <.icon name={if(@healthy_count == @total_count, do: "hero-check-circle", else: "hero-exclamation-triangle")} class={["size-5", if(@healthy_count == @total_count, do: "text-success", else: "text-warning")]} />
              </div>
              <div>
                <p class="text-xs font-medium text-base-content/50 uppercase">Services</p>
                <p class="text-xl font-bold">{@healthy_count}/{@total_count}</p>
              </div>
            </div>
          </div>
        </div>

        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-5">
            <div class="flex items-center gap-3">
              <div class={["flex items-center justify-center w-10 h-10 rounded-lg", if(@db_status.status == :healthy, do: "bg-success/10", else: "bg-error/10")]}>
                <.icon name="hero-circle-stack" class={["size-5", if(@db_status.status == :healthy, do: "text-success", else: "text-error")]} />
              </div>
              <div>
                <p class="text-xs font-medium text-base-content/50 uppercase">PostgreSQL</p>
                <p class="text-xl font-bold">{if @db_status.status == :healthy, do: "Connected", else: "Down"}</p>
              </div>
            </div>
          </div>
        </div>

        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-5">
            <div class="flex items-center gap-3">
              <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-info/10">
                <.icon name="hero-server" class="size-5 text-info" />
              </div>
              <div>
                <p class="text-xs font-medium text-base-content/50 uppercase">Databases</p>
                <p class="text-xl font-bold">{@db_count}</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      <%!-- Service Cards --%>
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        <div :for={svc <- @services} class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-4">
            <div class="flex items-center justify-between">
              <span class="font-medium text-sm">{svc.name}</span>
              <span class={["badge badge-sm", svc.status == :healthy && "badge-success", svc.status == :unreachable && "badge-error"]}>
                {if svc.status == :healthy, do: "Healthy", else: "Unreachable"}
              </span>
            </div>
            <div class="mt-2 text-xs text-base-content/50 space-y-1">
              <div class="flex justify-between">
                <span>Port</span>
                <span class="font-mono">{svc.port}</span>
              </div>
              <div class="flex justify-between">
                <span>Response</span>
                <span class="font-mono">{svc.response_time_ms}ms</span>
              </div>
              <div :if={svc[:checked_at]} class="flex justify-between">
                <span>Checked</span>
                <span>{Calendar.strftime(svc.checked_at, "%H:%M:%S")}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
  end
end
```

- [ ] **Step 3: Commit**

```bash
git add src/pki_platform_engine/lib/pki_platform_engine/system_health.ex \
        src/pki_platform_portal/lib/pki_platform_portal_web/live/system_live.ex
git commit -m "feat: add system health monitoring page"
```

---

### Task 7: Tenant Metrics Module

**Files:**
- Create: `src/pki_platform_engine/lib/pki_platform_engine/tenant_metrics.ex`

- [ ] **Step 1: Create TenantMetrics module**

```elixir
# src/pki_platform_engine/lib/pki_platform_engine/tenant_metrics.ex
defmodule PkiPlatformEngine.TenantMetrics do
  alias PkiPlatformEngine.TenantRepo

  def get_metrics(tenant) do
    %{
      db_size: get_db_size(tenant.database_name),
      ca_users: count_table(tenant, "ca", "ca_users"),
      ra_users: count_table(tenant, "ra", "ra_users"),
      certificates_issued: count_table(tenant, "ca", "issued_certificates"),
      active_certificates: count_where(tenant, "ca", "issued_certificates", "status = 'active'"),
      pending_csrs: count_where(tenant, "ra", "csr_requests", "status = 'pending'")
    }
  rescue
    _ -> %{db_size: 0, ca_users: 0, ra_users: 0, certificates_issued: 0, active_certificates: 0, pending_csrs: 0}
  end

  defp get_db_size(database_name) do
    case Ecto.Adapters.SQL.query(
           PkiPlatformEngine.PlatformRepo,
           "SELECT pg_database_size($1)",
           [database_name]
         ) do
      {:ok, %{rows: [[size]]}} -> size
      _ -> 0
    end
  end

  defp count_table(tenant, schema, table) do
    case TenantRepo.execute_sql(tenant, schema, "SELECT count(*) FROM #{table}", []) do
      {:ok, %{rows: [[count]]}} -> count
      _ -> 0
    end
  end

  defp count_where(tenant, schema, table, condition) do
    case TenantRepo.execute_sql(tenant, schema, "SELECT count(*) FROM #{table} WHERE #{condition}", []) do
      {:ok, %{rows: [[count]]}} -> count
      _ -> 0
    end
  end

  def format_bytes(bytes) when bytes < 1024, do: "#{bytes} B"
  def format_bytes(bytes) when bytes < 1_048_576, do: "#{Float.round(bytes / 1024, 1)} KB"
  def format_bytes(bytes) when bytes < 1_073_741_824, do: "#{Float.round(bytes / 1_048_576, 1)} MB"
  def format_bytes(bytes), do: "#{Float.round(bytes / 1_073_741_824, 1)} GB"
end
```

- [ ] **Step 2: Commit**

```bash
git add src/pki_platform_engine/lib/pki_platform_engine/tenant_metrics.ex
git commit -m "feat: add tenant metrics module for health queries"
```

---

### Task 8: Tenant Detail Page

**Files:**
- Create: `src/pki_platform_portal/lib/pki_platform_portal_web/live/tenant_detail_live.ex`

- [ ] **Step 1: Create TenantDetailLive**

```elixir
# src/pki_platform_portal/lib/pki_platform_portal_web/live/tenant_detail_live.ex
defmodule PkiPlatformPortalWeb.TenantDetailLive do
  use PkiPlatformPortalWeb, :live_view

  alias PkiPlatformEngine.Provisioner
  alias PkiPlatformEngine.TenantMetrics

  @impl true
  def mount(%{"id" => id}, _session, socket) do
    case Provisioner.get_tenant(id) do
      nil ->
        {:ok, socket |> put_flash(:error, "Tenant not found.") |> push_navigate(to: "/tenants")}

      tenant ->
        metrics = TenantMetrics.get_metrics(tenant)

        ca_host = System.get_env("CA_PORTAL_HOST", "ca.straptrust.com")
        ra_host = System.get_env("RA_PORTAL_HOST", "ra.straptrust.com")

        {:ok,
         assign(socket,
           page_title: "Tenant Detail",
           tenant: tenant,
           metrics: metrics,
           ca_setup_url: "https://#{ca_host}/setup?tenant=#{tenant.slug}",
           ra_setup_url: "https://#{ra_host}/setup?tenant=#{tenant.slug}"
         )}
    end
  end

  @impl true
  def handle_event("suspend", _params, socket) do
    case Provisioner.suspend_tenant(socket.assigns.tenant.id) do
      {:ok, tenant} ->
        {:noreply, socket |> assign(tenant: tenant) |> put_flash(:info, "Tenant suspended.")}
      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed: #{inspect(reason)}")}
    end
  end

  def handle_event("activate", _params, socket) do
    case Provisioner.activate_tenant(socket.assigns.tenant.id) do
      {:ok, tenant} ->
        {:noreply, socket |> assign(tenant: tenant) |> put_flash(:info, "Tenant activated.")}
      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed: #{inspect(reason)}")}
    end
  end

  def handle_event("delete", _params, socket) do
    case Provisioner.delete_tenant(socket.assigns.tenant.id) do
      {:ok, _} ->
        {:noreply, socket |> put_flash(:info, "Tenant deleted.") |> push_navigate(to: "/tenants")}
      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed: #{inspect(reason)}")}
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div id="tenant-detail" class="space-y-6">
      <%!-- Back link --%>
      <.link navigate="/tenants" class="text-sm text-primary hover:underline flex items-center gap-1">
        <.icon name="hero-arrow-left" class="size-4" /> Back to Tenants
      </.link>

      <%!-- Tenant Info --%>
      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-5">
          <div class="flex items-center justify-between mb-4">
            <h2 class="text-lg font-bold">{@tenant.name}</h2>
            <span class={["badge", @tenant.status == "active" && "badge-success", @tenant.status == "suspended" && "badge-warning", @tenant.status == "initialized" && "badge-ghost"]}>
              {@tenant.status}
            </span>
          </div>

          <div class="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            <div>
              <p class="text-xs text-base-content/50 uppercase">Slug</p>
              <p class="font-mono">{@tenant.slug}</p>
            </div>
            <div>
              <p class="text-xs text-base-content/50 uppercase">Algorithm</p>
              <p class="font-mono">{@tenant.signing_algorithm}</p>
            </div>
            <div>
              <p class="text-xs text-base-content/50 uppercase">Database</p>
              <p class="font-mono text-xs">{@tenant.database_name}</p>
            </div>
            <div>
              <p class="text-xs text-base-content/50 uppercase">Created</p>
              <p>{Calendar.strftime(@tenant.inserted_at, "%Y-%m-%d %H:%M")}</p>
            </div>
          </div>

          <div class="flex gap-2 mt-4">
            <button
              :if={@tenant.status in ["initialized", "active"]}
              phx-click="suspend" data-confirm="Suspend this tenant?"
              class="btn btn-warning btn-sm"
            >Suspend</button>
            <button
              :if={@tenant.status == "suspended"}
              phx-click="activate"
              class="btn btn-success btn-sm"
            >Activate</button>
            <button
              :if={@tenant.status == "suspended"}
              phx-click="delete" data-confirm="Permanently delete this tenant and its database?"
              class="btn btn-error btn-sm"
            >Delete</button>
          </div>
        </div>
      </div>

      <%!-- Setup Status --%>
      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-5">
          <h3 class="text-sm font-semibold mb-3">Admin Setup Status</h3>
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div class="border border-base-300 rounded-lg p-4">
              <div class="flex items-center justify-between mb-2">
                <span class="font-medium text-sm">CA Admin</span>
                <span class={["badge badge-sm", if(@metrics.ca_users > 0, do: "badge-success", else: "badge-warning")]}>
                  {if @metrics.ca_users > 0, do: "Configured", else: "Pending setup"}
                </span>
              </div>
              <p :if={@metrics.ca_users == 0} class="text-xs text-base-content/50 break-all">
                Setup URL: <span class="font-mono text-primary select-all">{@ca_setup_url}</span>
              </p>
              <p :if={@metrics.ca_users > 0} class="text-xs text-base-content/50">{@metrics.ca_users} user(s)</p>
            </div>

            <div class="border border-base-300 rounded-lg p-4">
              <div class="flex items-center justify-between mb-2">
                <span class="font-medium text-sm">RA Admin</span>
                <span class={["badge badge-sm", if(@metrics.ra_users > 0, do: "badge-success", else: "badge-warning")]}>
                  {if @metrics.ra_users > 0, do: "Configured", else: "Pending setup"}
                </span>
              </div>
              <p :if={@metrics.ra_users == 0} class="text-xs text-base-content/50 break-all">
                Setup URL: <span class="font-mono text-primary select-all">{@ra_setup_url}</span>
              </p>
              <p :if={@metrics.ra_users > 0} class="text-xs text-base-content/50">{@metrics.ra_users} user(s)</p>
            </div>
          </div>
        </div>
      </div>

      <%!-- Health Metrics --%>
      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-5">
          <h3 class="text-sm font-semibold mb-3">Health Metrics</h3>
          <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
            <div class="text-center p-3 rounded-lg bg-base-200">
              <p class="text-xs text-base-content/50 uppercase">DB Size</p>
              <p class="text-lg font-bold">{PkiPlatformEngine.TenantMetrics.format_bytes(@metrics.db_size)}</p>
            </div>
            <div class="text-center p-3 rounded-lg bg-base-200">
              <p class="text-xs text-base-content/50 uppercase">CA Users</p>
              <p class="text-lg font-bold">{@metrics.ca_users}</p>
            </div>
            <div class="text-center p-3 rounded-lg bg-base-200">
              <p class="text-xs text-base-content/50 uppercase">RA Users</p>
              <p class="text-lg font-bold">{@metrics.ra_users}</p>
            </div>
            <div class="text-center p-3 rounded-lg bg-base-200">
              <p class="text-xs text-base-content/50 uppercase">Certs Issued</p>
              <p class="text-lg font-bold">{@metrics.certificates_issued}</p>
            </div>
            <div class="text-center p-3 rounded-lg bg-base-200">
              <p class="text-xs text-base-content/50 uppercase">Active Certs</p>
              <p class="text-lg font-bold">{@metrics.active_certificates}</p>
            </div>
            <div class="text-center p-3 rounded-lg bg-base-200">
              <p class="text-xs text-base-content/50 uppercase">Pending CSRs</p>
              <p class="text-lg font-bold">{@metrics.pending_csrs}</p>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
  end
end
```

- [ ] **Step 2: Commit**

```bash
git add src/pki_platform_portal/lib/pki_platform_portal_web/live/tenant_detail_live.ex
git commit -m "feat: add tenant detail page with health metrics and setup status"
```

---

### Task 9: Tenant Creation Page & Updated Tenants List

**Files:**
- Create: `src/pki_platform_portal/lib/pki_platform_portal_web/live/tenant_new_live.ex`
- Modify: `src/pki_platform_portal/lib/pki_platform_portal_web/live/tenants_live.ex`

- [ ] **Step 1: Create TenantNewLive**

```elixir
# src/pki_platform_portal/lib/pki_platform_portal_web/live/tenant_new_live.ex
defmodule PkiPlatformPortalWeb.TenantNewLive do
  use PkiPlatformPortalWeb, :live_view

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     assign(socket,
       page_title: "New Tenant",
       form_error: nil,
       created_tenant: nil
     )}
  end

  @impl true
  def handle_event("create_tenant", %{"name" => name, "slug" => slug} = params, socket) do
    opts =
      case Map.get(params, "signing_algorithm", "") do
        "" -> []
        algo -> [signing_algorithm: algo]
      end

    case PkiPlatformEngine.Provisioner.create_tenant(name, slug, opts) do
      {:ok, tenant} ->
        ca_host = System.get_env("CA_PORTAL_HOST", "ca.straptrust.com")
        ra_host = System.get_env("RA_PORTAL_HOST", "ra.straptrust.com")

        {:noreply,
         assign(socket,
           created_tenant: tenant,
           ca_setup_url: "https://#{ca_host}/setup?tenant=#{tenant.slug}",
           ra_setup_url: "https://#{ra_host}/setup?tenant=#{tenant.slug}",
           form_error: nil
         )}

      {:error, %Ecto.Changeset{} = changeset} ->
        errors =
          Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
            Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
              opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
            end)
          end)

        error_msg = errors |> Enum.map(fn {k, v} -> "#{k}: #{Enum.join(v, ", ")}" end) |> Enum.join("; ")
        {:noreply, assign(socket, form_error: error_msg)}

      {:error, reason} ->
        {:noreply, assign(socket, form_error: "Failed to create tenant: #{inspect(reason)}")}
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div id="tenant-new" class="space-y-6">
      <.link navigate="/tenants" class="text-sm text-primary hover:underline flex items-center gap-1">
        <.icon name="hero-arrow-left" class="size-4" /> Back to Tenants
      </.link>

      <%= if @created_tenant do %>
        <%!-- Success state --%>
        <div class="card bg-base-100 shadow-sm border border-success/30">
          <div class="card-body p-6">
            <div class="flex items-center gap-3 mb-4">
              <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-success/10">
                <.icon name="hero-check-circle" class="size-5 text-success" />
              </div>
              <div>
                <h2 class="text-lg font-bold">Tenant Created</h2>
                <p class="text-sm text-base-content/60">{@created_tenant.name} ({@created_tenant.slug})</p>
              </div>
            </div>

            <p class="text-sm mb-4">Share these setup URLs with the designated administrators:</p>

            <div class="space-y-3">
              <div class="border border-base-300 rounded-lg p-4">
                <p class="text-xs font-medium text-base-content/50 uppercase mb-1">CA Admin Setup URL</p>
                <p class="font-mono text-sm text-primary select-all break-all">{@ca_setup_url}</p>
              </div>
              <div class="border border-base-300 rounded-lg p-4">
                <p class="text-xs font-medium text-base-content/50 uppercase mb-1">RA Admin Setup URL</p>
                <p class="font-mono text-sm text-primary select-all break-all">{@ra_setup_url}</p>
              </div>
            </div>

            <div class="flex gap-2 mt-4">
              <.link navigate={"/tenants/#{@created_tenant.id}"} class="btn btn-primary btn-sm">View Tenant</.link>
              <.link navigate="/tenants" class="btn btn-ghost btn-sm">Back to List</.link>
            </div>
          </div>
        </div>
      <% else %>
        <%!-- Create form --%>
        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-5">
            <h2 class="text-lg font-bold mb-4">Create New Tenant</h2>

            <%= if @form_error do %>
              <div class="alert alert-error text-sm mb-3">
                <.icon name="hero-exclamation-circle" class="size-4" />
                <span>{@form_error}</span>
              </div>
            <% end %>

            <form phx-submit="create_tenant" class="space-y-4">
              <div>
                <label class="block text-sm font-medium mb-1">Tenant Name</label>
                <input type="text" name="name" required class="input input-bordered w-full" placeholder="Organization Name" />
              </div>
              <div>
                <label class="block text-sm font-medium mb-1">Slug</label>
                <input type="text" name="slug" required class="input input-bordered w-full" placeholder="org-name" pattern="[a-z0-9][a-z0-9-]*[a-z0-9]" title="Lowercase alphanumeric with hyphens" />
                <p class="text-xs text-base-content/50 mt-1">Used in setup URLs. Lowercase letters, numbers, and hyphens only.</p>
              </div>
              <div>
                <label class="block text-sm font-medium mb-1">Default Signing Algorithm</label>
                <select name="signing_algorithm" class="select select-bordered w-full">
                  <optgroup label="Classical">
                    <option value="ECC-P256" selected>ECC-P256</option>
                    <option value="ECC-P384">ECC-P384</option>
                    <option value="RSA-2048">RSA-2048</option>
                    <option value="RSA-4096">RSA-4096</option>
                  </optgroup>
                  <optgroup label="Post-Quantum">
                    <option value="KAZ-SIGN-128">KAZ-SIGN-128</option>
                    <option value="KAZ-SIGN-192">KAZ-SIGN-192</option>
                    <option value="KAZ-SIGN-256">KAZ-SIGN-256</option>
                    <option value="ML-DSA-44">ML-DSA-44</option>
                    <option value="ML-DSA-65">ML-DSA-65</option>
                    <option value="ML-DSA-87">ML-DSA-87</option>
                  </optgroup>
                </select>
              </div>
              <div class="flex justify-end">
                <button type="submit" class="btn btn-primary" phx-disable-with="Creating tenant...">
                  <.icon name="hero-plus" class="size-4" /> Create Tenant
                </button>
              </div>
            </form>
          </div>
        </div>
      <% end %>
    </div>
    """
  end
end
```

- [ ] **Step 2: Update TenantsLive — remove inline form, add New Tenant button, make rows clickable**

Replace the full `render/1` in `tenants_live.ex`. Keep the `mount`, `handle_event` functions for suspend/activate/delete/change_page but remove `create_tenant`:

In `tenants_live.ex`, remove the `handle_event("create_tenant", ...)` clause (lines 21-45) and the `form_error` assign from mount. Then replace the render function's template to remove the create form and add a "New Tenant" button + clickable rows:

The key changes to `tenants_live.ex`:
1. Remove `form_error: nil` from mount assigns
2. Remove `handle_event("create_tenant", ...)`
3. Replace the create form section with a header bar containing "New Tenant" button
4. Make tenant name a link to `/tenants/:id`

- [ ] **Step 3: Commit**

```bash
git add src/pki_platform_portal/lib/pki_platform_portal_web/live/tenant_new_live.ex \
        src/pki_platform_portal/lib/pki_platform_portal_web/live/tenants_live.ex
git commit -m "feat: add tenant creation page with setup URLs, update tenant list"
```

---

### Task 10: Update Dashboard with Setup Summary

**Files:**
- Modify: `src/pki_platform_portal/lib/pki_platform_portal_web/live/dashboard_live.ex`

- [ ] **Step 1: Update dashboard to show service health summary and pending setup count**

Add to mount: count tenants with `initialized` status (pending setup). Add a service health summary card. The key additions:

```elixir
# In mount, add:
initialized = Enum.count(tenants, &(&1.status == "initialized"))
services = PkiPlatformEngine.SystemHealth.check_all()
healthy_services = Enum.count(services, &(&1.status == :healthy))
total_services = length(services)

# Add to assigns:
initialized_tenants: initialized,
healthy_services: healthy_services,
total_services: total_services,
```

Add a "Pending Setup" stat card and a "System Health" stat card to the dashboard grid.

- [ ] **Step 2: Commit**

```bash
git add src/pki_platform_portal/lib/pki_platform_portal_web/live/dashboard_live.ex
git commit -m "feat: add setup status and service health to dashboard"
```

---

### Task 11: RA Engine Multi-Tenancy

**Files:**
- Create: `src/pki_ra_engine/priv/repo/migrations/20260330000001_add_tenant_id_to_ra_users.exs`
- Modify: `src/pki_ra_engine/lib/pki_ra_engine/schema/ra_user.ex`
- Modify: `src/pki_ra_engine/lib/pki_ra_engine/user_management.ex`
- Modify: `src/pki_ra_engine/lib/pki_ra_engine/api/user_controller.ex`

- [ ] **Step 1: Create migration**

```elixir
# src/pki_ra_engine/priv/repo/migrations/20260330000001_add_tenant_id_to_ra_users.exs
defmodule PkiRaEngine.Repo.Migrations.AddTenantIdToRaUsers do
  use Ecto.Migration

  def change do
    alter table(:ra_users) do
      add :tenant_id, :uuid
    end

    create index(:ra_users, [:tenant_id])
  end
end
```

- [ ] **Step 2: Update RaUser schema**

In `src/pki_ra_engine/lib/pki_ra_engine/schema/ra_user.ex`, add `tenant_id` field after the `status` field (around line 17):

```elixir
field :tenant_id, :binary_id
```

Update `changeset/2` to cast `tenant_id`:

```elixir
|> cast(attrs, [:username, :display_name, :role, :status, :tenant_id])
```

Update `registration_changeset/2` to cast `tenant_id`:

```elixir
|> cast(attrs, [:username, :display_name, :role, :password, :tenant_id])
```

- [ ] **Step 3: Update UserManagement to filter by tenant_id**

In `src/pki_ra_engine/lib/pki_ra_engine/user_management.ex`, update `list_users/1` to support `:tenant_id` filter. In `build_query/2` (or wherever filters are applied), add:

```elixir
defp maybe_filter_tenant(query, opts) do
  case Keyword.get(opts, :tenant_id) do
    nil -> query
    tenant_id -> from(u in query, where: u.tenant_id == ^tenant_id)
  end
end
```

Update `needs_setup?/0` to accept optional `tenant_id`:

```elixir
def needs_setup?(tenant_id \\ nil) do
  query = from(u in RaUser, where: u.role == "ra_admin")
  query = if tenant_id, do: from(u in query, where: u.tenant_id == ^tenant_id), else: query
  Repo.aggregate(query, :count) == 0
end
```

- [ ] **Step 4: Update UserController to accept tenant_id**

In `src/pki_ra_engine/lib/pki_ra_engine/api/user_controller.ex`, update `build_attrs/1` to include `tenant_id`:

```elixir
defp build_attrs(params) do
  %{
    username: params["username"],
    display_name: params["display_name"] || params["username"],
    role: params["role"] || "ra_officer",
    tenant_id: params["tenant_id"]
  }
end
```

Update `build_filters/1` to pass `tenant_id`:

```elixir
defp build_filters(params) do
  []
  |> maybe_add_filter(:role, params, "role")
  |> maybe_add_filter(:status, params, "status")
  |> maybe_add_filter(:tenant_id, params, "tenant_id")
end
```

Update `serialize_user/1` to include `tenant_id`:

```elixir
defp serialize_user(user) do
  %{
    id: user.id,
    username: user.username,
    display_name: user.display_name,
    role: user.role,
    status: user.status,
    tenant_id: user.tenant_id,
    inserted_at: user.inserted_at
  }
end
```

- [ ] **Step 5: Run migration**

Run: `cd src/pki_ra_engine && MIX_ENV=dev mix ecto.migrate`

- [ ] **Step 6: Commit**

```bash
git add src/pki_ra_engine/priv/repo/migrations/20260330000001_add_tenant_id_to_ra_users.exs \
        src/pki_ra_engine/lib/pki_ra_engine/schema/ra_user.ex \
        src/pki_ra_engine/lib/pki_ra_engine/user_management.ex \
        src/pki_ra_engine/lib/pki_ra_engine/api/user_controller.ex
git commit -m "feat: add tenant_id to RA engine for multi-tenancy"
```

---

### Task 12: CA Portal Tenant-Aware Setup

**Files:**
- Modify: `src/pki_ca_portal/lib/pki_ca_portal_web/controllers/setup_controller.ex`

- [ ] **Step 1: Update CA setup to accept tenant slug**

The CA portal setup needs to:
1. Read `?tenant=slug` from query params
2. Look up the tenant via PlatformEngine
3. Validate tenant exists and is not suspended
4. Find or create a CA instance for this tenant
5. Create the CA admin scoped to that instance

Update `new/2` to validate tenant param:

```elixir
def new(conn, params) do
  case validate_tenant(params) do
    {:ok, tenant} ->
      if PkiCaEngine.UserManagement.needs_setup?(tenant_ca_instance_id(tenant)) do
        render(conn, :setup, layout: false, error: nil, tenant: tenant)
      else
        render(conn, :setup_complete, layout: false, tenant: tenant)
      end

    {:error, message} ->
      render(conn, :setup_error, layout: false, error: message)
  end
end
```

Add `validate_tenant/1`:

```elixir
defp validate_tenant(%{"tenant" => slug}) when is_binary(slug) and slug != "" do
  case PkiPlatformEngine.Provisioner.get_tenant_by_slug(slug) do
    nil -> {:error, "Tenant not found."}
    %{status: "suspended"} -> {:error, "Tenant is suspended."}
    tenant -> {:ok, tenant}
  end
end

defp validate_tenant(_), do: {:error, "Tenant not specified. Contact your platform administrator."}
```

Update `create/2` to scope the admin to the tenant's CA instance:

```elixir
def create(conn, %{"tenant_slug" => slug} = params) do
  # ... validate params, look up tenant, create admin with ca_instance_id
end
```

Note: The exact implementation depends on how `ca_instance_id` maps to tenants. The CA engine currently uses a "default" instance. For multi-tenancy, each tenant needs its own CA instance (or reuse "default" with tenant scoping). The simplest approach is to create a CA instance named after the tenant slug.

- [ ] **Step 2: Add setup_error and setup_complete templates**

Create error and completion templates that the setup controller renders.

- [ ] **Step 3: Commit**

```bash
git add src/pki_ca_portal/lib/pki_ca_portal_web/controllers/setup_controller.ex \
        src/pki_ca_portal/lib/pki_ca_portal_web/controllers/setup_html/
git commit -m "feat: make CA portal setup tenant-aware"
```

---

### Task 13: RA Portal Tenant-Aware Setup

**Files:**
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/controllers/setup_controller.ex`

- [ ] **Step 1: Update RA setup to accept tenant slug**

Same pattern as CA portal. Update `new/2`:

```elixir
def new(conn, params) do
  case validate_tenant(params) do
    {:ok, tenant} ->
      if PkiRaEngine.UserManagement.needs_setup?(tenant.id) do
        render(conn, :setup, layout: false, error: nil, tenant: tenant)
      else
        render(conn, :setup_complete, layout: false, tenant: tenant)
      end

    {:error, message} ->
      render(conn, :setup_error, layout: false, error: message)
  end
end
```

Add `validate_tenant/1`:

```elixir
defp validate_tenant(%{"tenant" => slug}) when is_binary(slug) and slug != "" do
  case PkiPlatformEngine.Provisioner.get_tenant_by_slug(slug) do
    nil -> {:error, "Tenant not found."}
    %{status: "suspended"} -> {:error, "Tenant is suspended."}
    tenant -> {:ok, tenant}
  end
end

defp validate_tenant(_), do: {:error, "Tenant not specified. Contact your platform administrator."}
```

Update `create/2` to include `tenant_id` when registering the user:

```elixir
def create(conn, %{"tenant_slug" => slug} = params) do
  tenant = PkiPlatformEngine.Provisioner.get_tenant_by_slug(slug)

  case validate_setup_params(params) do
    :ok ->
      attrs = %{
        username: params["username"],
        display_name: params["display_name"] || params["username"],
        password: params["password"],
        role: "ra_admin",
        tenant_id: tenant.id
      }

      case PkiRaEngine.UserManagement.register_user(attrs) do
        {:ok, _user} ->
          conn |> put_flash(:info, "RA Admin created.") |> redirect(to: "/login")
        {:error, changeset} ->
          render(conn, :setup, layout: false, error: format_changeset_error(changeset), tenant: tenant)
      end

    {:error, msg} ->
      render(conn, :setup, layout: false, error: msg, tenant: tenant)
  end
end
```

- [ ] **Step 2: Add setup_error and setup_complete templates**

- [ ] **Step 3: Commit**

```bash
git add src/pki_ra_portal/lib/pki_ra_portal_web/controllers/setup_controller.ex \
        src/pki_ra_portal/lib/pki_ra_portal_web/controllers/setup_html/
git commit -m "feat: make RA portal setup tenant-aware"
```

---

### Task 14: Backward Compatibility — Env Var Seeding

**Files:**
- Modify: `src/pki_platform_portal/lib/pki_platform_portal/application.ex` (or equivalent startup module)

- [ ] **Step 1: Add env var seeding on application start**

In the platform portal's `Application.start/2`, after the supervisor starts, call the seeding function:

```elixir
# After Supervisor.start_link(children, opts)
PkiPlatformEngine.AdminManagement.seed_from_env()
```

This ensures that if `PLATFORM_ADMIN_USERNAME` and `PLATFORM_ADMIN_PASSWORD` are set in `.env` and no admin exists yet, the first admin is auto-created.

- [ ] **Step 2: Commit**

```bash
git add src/pki_platform_portal/lib/pki_platform_portal/application.ex
git commit -m "feat: seed first admin from env vars for backward compatibility"
```

---

### Task 15: Integration Testing & Deployment

- [ ] **Step 1: Run all migrations on dev**

```bash
cd src/pki_platform_engine && MIX_ENV=dev mix ecto.migrate
cd ../pki_ra_engine && MIX_ENV=dev mix ecto.migrate
```

- [ ] **Step 2: Compile all projects**

```bash
cd src/pki_platform_portal && MIX_ENV=dev mix compile
cd ../pki_ca_portal && MIX_ENV=dev mix compile
cd ../pki_ra_portal && MIX_ENV=dev mix compile
cd ../pki_ra_engine && MIX_ENV=dev mix compile
```

- [ ] **Step 3: Manual smoke test**

1. Start platform portal — should redirect to `/setup`
2. Create first admin on `/setup`
3. Login with new admin credentials
4. Verify sidebar shows Dashboard, Tenants, System, Admins
5. Create a tenant via `/tenants/new`
6. Verify setup URLs are shown
7. View tenant detail via `/tenants/:id`
8. Check system health page
9. Create additional admin via `/admins`

- [ ] **Step 4: Commit final changes**

```bash
git add -A
git commit -m "feat: complete admin portal with setup, metrics, monitoring, and admin management"
```
