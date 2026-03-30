# Forgot Password Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add self-service password reset via 6-digit email code to all 3 portals (Platform Admin, CA, RA).

**Architecture:** Each engine gets an `email` field on its user schema + a `get_user_by_username` function. CA/RA portals call their engine's new API endpoint to look up users, then use the existing `PkiPlatformEngine.EmailVerification` GenServer to generate/verify codes and `PkiPlatformEngine.Mailer` to send them. Each portal gets a `ForgotPasswordController` with a 3-step form flow (username → code + new password → success).

**Tech Stack:** Phoenix controllers, Ecto migrations, Plug.Router, Req HTTP client, ETS (EmailVerification), Resend API (Mailer), DaisyUI/Tailwind templates.

---

## File Map

### Engine changes (schema + context + API)

| File | Action | Purpose |
|------|--------|---------|
| `src/pki_platform_engine/priv/platform_repo/migrations/20260330000003_add_email_to_platform_admins.exs` | Create | Migration: add email to platform_admins |
| `src/pki_platform_engine/lib/pki_platform_engine/platform_admin.ex` | Modify | Add email field + changeset |
| `src/pki_platform_engine/lib/pki_platform_engine/admin_management.ex` | Modify | Add `get_admin_by_username/1`, `reset_admin_password/2` |
| `src/pki_platform_engine/lib/pki_platform_engine/email_templates.ex` | Modify | Add `password_reset_code/1` template |
| `src/pki_ca_engine/priv/repo/migrations/20260330000003_add_email_to_ca_users.exs` | Create | Migration: add email to ca_users |
| `src/pki_ca_engine/lib/pki_ca_engine/schema/ca_user.ex` | Modify | Add email field + changeset |
| `src/pki_ca_engine/lib/pki_ca_engine/user_management.ex` | Modify | Add `get_user_by_username/2` |
| `src/pki_ca_engine/lib/pki_ca_engine/api/auth_router.ex` | Modify | Add `GET /user-by-username/:username` |
| `src/pki_ca_engine/lib/pki_ca_engine/api/auth_controller.ex` | Modify | Add `user_by_username/2` action |
| `src/pki_ra_engine/priv/repo/migrations/20260330000003_add_email_to_ra_users.exs` | Create | Migration: add email to ra_users |
| `src/pki_ra_engine/lib/pki_ra_engine/schema/ra_user.ex` | Modify | Add email field + changeset |
| `src/pki_ra_engine/lib/pki_ra_engine/user_management.ex` | Modify | Add `get_user_by_username/1` |
| `src/pki_ra_engine/lib/pki_ra_engine/api/auth_router.ex` | Modify | Add `GET /user-by-username/:username` |
| `src/pki_ra_engine/lib/pki_ra_engine/api/auth_controller.ex` | Modify | Add `user_by_username/2` action |

### Portal changes (controller + templates + routes)

| File | Action | Purpose |
|------|--------|---------|
| `src/pki_platform_portal/lib/pki_platform_portal_web/controllers/forgot_password_controller.ex` | Create | 3-step forgot password flow |
| `src/pki_platform_portal/lib/pki_platform_portal_web/controllers/forgot_password_html.ex` | Create | View module |
| `src/pki_platform_portal/lib/pki_platform_portal_web/controllers/forgot_password_html/new.html.heex` | Create | Username form |
| `src/pki_platform_portal/lib/pki_platform_portal_web/controllers/forgot_password_html/code.html.heex` | Create | Code + new password form |
| `src/pki_platform_portal/lib/pki_platform_portal_web/router.ex` | Modify | Add forgot-password routes |
| `src/pki_platform_portal/lib/pki_platform_portal_web/controllers/session_html/login.html.heex` | Modify | Add "Forgot password?" link |
| `src/pki_ca_portal/lib/pki_ca_portal_web/controllers/forgot_password_controller.ex` | Create | 3-step forgot password flow |
| `src/pki_ca_portal/lib/pki_ca_portal_web/controllers/forgot_password_html.ex` | Create | View module |
| `src/pki_ca_portal/lib/pki_ca_portal_web/controllers/forgot_password_html/new.html.heex` | Create | Username form |
| `src/pki_ca_portal/lib/pki_ca_portal_web/controllers/forgot_password_html/code.html.heex` | Create | Code + new password form |
| `src/pki_ca_portal/lib/pki_ca_portal_web/router.ex` | Modify | Add forgot-password routes |
| `src/pki_ca_portal/lib/pki_ca_portal_web/controllers/session_html/login.html.heex` | Modify | Add "Forgot password?" link |
| `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client.ex` | Modify | Add `get_user_by_username/1` callback |
| `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/http.ex` | Modify | Implement HTTP `get_user_by_username/1` |
| `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/mock.ex` | Modify | Implement mock `get_user_by_username/1` |
| `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/stateful_mock.ex` | Modify | Implement mock `get_user_by_username/1` |
| `src/pki_ra_portal/lib/pki_ra_portal_web/controllers/forgot_password_controller.ex` | Create | 3-step forgot password flow |
| `src/pki_ra_portal/lib/pki_ra_portal_web/controllers/forgot_password_html.ex` | Create | View module |
| `src/pki_ra_portal/lib/pki_ra_portal_web/controllers/forgot_password_html/new.html.heex` | Create | Username form |
| `src/pki_ra_portal/lib/pki_ra_portal_web/controllers/forgot_password_html/code.html.heex` | Create | Code + new password form |
| `src/pki_ra_portal/lib/pki_ra_portal_web/router.ex` | Modify | Add forgot-password routes |
| `src/pki_ra_portal/lib/pki_ra_portal_web/controllers/session_html/login.html.heex` | Modify | Add "Forgot password?" link |
| `src/pki_ra_portal/lib/pki_ra_portal/ra_engine_client.ex` | Modify | Add `get_user_by_username/1` callback |
| `src/pki_ra_portal/lib/pki_ra_portal/ra_engine_client/http.ex` | Modify | Implement HTTP `get_user_by_username/1` |

---

## Task 1: Add email field to all 3 user schemas + migrations

**Files:**
- Create: `src/pki_platform_engine/priv/platform_repo/migrations/20260330000003_add_email_to_platform_admins.exs`
- Create: `src/pki_ca_engine/priv/repo/migrations/20260330000003_add_email_to_ca_users.exs`
- Create: `src/pki_ra_engine/priv/repo/migrations/20260330000003_add_email_to_ra_users.exs`
- Modify: `src/pki_platform_engine/lib/pki_platform_engine/platform_admin.ex`
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/schema/ca_user.ex`
- Modify: `src/pki_ra_engine/lib/pki_ra_engine/schema/ra_user.ex`

- [ ] **Step 1: Create Platform Engine migration**

```elixir
# src/pki_platform_engine/priv/platform_repo/migrations/20260330000003_add_email_to_platform_admins.exs
defmodule PkiPlatformEngine.PlatformRepo.Migrations.AddEmailToPlatformAdmins do
  use Ecto.Migration

  def change do
    alter table(:platform_admins) do
      add :email, :string
    end
  end
end
```

- [ ] **Step 2: Create CA Engine migration**

```elixir
# src/pki_ca_engine/priv/repo/migrations/20260330000003_add_email_to_ca_users.exs
defmodule PkiCaEngine.Repo.Migrations.AddEmailToCaUsers do
  use Ecto.Migration

  def change do
    alter table(:ca_users) do
      add :email, :string
    end
  end
end
```

- [ ] **Step 3: Create RA Engine migration**

```elixir
# src/pki_ra_engine/priv/repo/migrations/20260330000003_add_email_to_ra_users.exs
defmodule PkiRaEngine.Repo.Migrations.AddEmailToRaUsers do
  use Ecto.Migration

  def change do
    alter table(:ra_users) do
      add :email, :string
    end
  end
end
```

- [ ] **Step 4: Add email field to PlatformAdmin schema**

In `src/pki_platform_engine/lib/pki_platform_engine/platform_admin.ex`, add `field :email, :string` to the schema block (after `field :status`). Update `changeset/2` to cast `:email`. Update `registration_changeset/2` to cast `:email`.

```elixir
# In the schema block, add after line 13 (field :status):
    field :email, :string

# In changeset/2, change the cast list:
    |> cast(attrs, [:username, :display_name, :status, :email])

# In registration_changeset/2, change the cast list:
    |> cast(attrs, [:username, :display_name, :password, :email])
```

- [ ] **Step 5: Add email field to CaUser schema**

In `src/pki_ca_engine/lib/pki_ca_engine/schema/ca_user.ex`, add `field :email, :string` to the schema block (after `field :credential_expires_at`). Update `changeset/2` and `registration_changeset/2` to include `:email` in the cast list.

```elixir
# In the schema block, add after field :credential_expires_at (line 19):
    field :email, :string

# In changeset/2, add :email to the cast list (line 32):
    |> cast(attrs, [:ca_instance_id, :username, :display_name, :role, :status, :must_change_password, :credential_expires_at, :email])

# In registration_changeset/2, add :email to the cast list (line 42):
    |> cast(attrs, [:ca_instance_id, :username, :password, :display_name, :role, :must_change_password, :credential_expires_at, :email])
```

- [ ] **Step 6: Add email field to RaUser schema**

Same pattern as CaUser. Add `field :email, :string` to schema. Update cast lists in `changeset/2` and `registration_changeset/2`.

- [ ] **Step 7: Run migrations**

```bash
cd src/pki_platform_engine && mix ecto.migrate --prefix platform_repo
cd src/pki_ca_engine && mix ecto.migrate
cd src/pki_ra_engine && mix ecto.migrate
```

- [ ] **Step 8: Commit**

```bash
git add src/pki_platform_engine/priv/platform_repo/migrations/20260330000003_add_email_to_platform_admins.exs \
        src/pki_ca_engine/priv/repo/migrations/20260330000003_add_email_to_ca_users.exs \
        src/pki_ra_engine/priv/repo/migrations/20260330000003_add_email_to_ra_users.exs \
        src/pki_platform_engine/lib/pki_platform_engine/platform_admin.ex \
        src/pki_ca_engine/lib/pki_ca_engine/schema/ca_user.ex \
        src/pki_ra_engine/lib/pki_ra_engine/schema/ra_user.ex
git commit -m "feat: add email field to all user schemas for password reset"
```

---

## Task 2: Add password reset email template

**Files:**
- Modify: `src/pki_platform_engine/lib/pki_platform_engine/email_templates.ex`

- [ ] **Step 1: Add `password_reset_code/1` function**

Add this function to `PkiPlatformEngine.EmailTemplates` after the existing `admin_credentials/7` function (after line 77):

```elixir
  def password_reset_code(code) do
    """
    <!DOCTYPE html>
    <html>
    <head><meta charset="utf-8"></head>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 560px; margin: 0 auto; padding: 40px 20px; color: #1a1a2e;">
      <div style="text-align: center; margin-bottom: 32px;">
        <div style="display: inline-block; background: #661ae6; border-radius: 12px; padding: 12px; margin-bottom: 16px;">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
        </div>
        <h1 style="font-size: 24px; font-weight: 700; margin: 0;">PQC PKI Platform</h1>
      </div>
      <div style="background: #f8f9fa; border-radius: 12px; padding: 32px; text-align: center; margin-bottom: 24px;">
        <p style="font-size: 14px; color: #6b7280; margin: 0 0 16px;">Your password reset code is:</p>
        <div style="font-size: 36px; font-weight: 700; letter-spacing: 8px; color: #661ae6; font-family: monospace;">#{code}</div>
        <p style="font-size: 12px; color: #9ca3af; margin: 16px 0 0;">This code expires in 10 minutes.</p>
      </div>
      <p style="font-size: 13px; color: #9ca3af; text-align: center;">If you did not request a password reset, you can safely ignore this email.</p>
    </body>
    </html>
    """
  end
```

- [ ] **Step 2: Commit**

```bash
git add src/pki_platform_engine/lib/pki_platform_engine/email_templates.ex
git commit -m "feat: add password reset code email template"
```

---

## Task 3: Add engine-side user lookup functions

**Files:**
- Modify: `src/pki_platform_engine/lib/pki_platform_engine/admin_management.ex`
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/user_management.ex`
- Modify: `src/pki_ra_engine/lib/pki_ra_engine/user_management.ex`

- [ ] **Step 1: Add `get_admin_by_username/1` and `reset_admin_password/2` to AdminManagement**

Add these functions to `PkiPlatformEngine.AdminManagement` (after `authenticate/2`, around line 33):

```elixir
  def get_admin_by_username(username) do
    case PlatformRepo.one(from(a in PlatformAdmin, where: a.username == ^username and a.status == "active")) do
      nil -> {:error, :not_found}
      admin -> {:ok, admin}
    end
  end

  def reset_admin_password(admin_id, new_password) do
    case PlatformRepo.get(PlatformAdmin, admin_id) do
      nil ->
        {:error, :not_found}

      admin ->
        admin
        |> PlatformAdmin.registration_changeset(%{password: new_password})
        |> PlatformRepo.update()
    end
  end
```

Note: `registration_changeset` is reused here because it handles password hashing. We need a dedicated `password_changeset` on PlatformAdmin. Add it:

In `src/pki_platform_engine/lib/pki_platform_engine/platform_admin.ex`, add after `registration_changeset/2`:

```elixir
  def password_changeset(admin, attrs) do
    admin
    |> cast(attrs, [:password])
    |> validate_required([:password])
    |> validate_length(:password, min: 8)
    |> hash_password()
  end
```

Then update `reset_admin_password/2` to use it:

```elixir
  def reset_admin_password(admin_id, new_password) do
    case PlatformRepo.get(PlatformAdmin, admin_id) do
      nil ->
        {:error, :not_found}

      admin ->
        admin
        |> PlatformAdmin.password_changeset(%{password: new_password})
        |> PlatformRepo.update()
    end
  end
```

- [ ] **Step 2: Add `get_user_by_username/2` to CA Engine UserManagement**

Add to `PkiCaEngine.UserManagement` (after `authenticate/2`, around line 74):

```elixir
  @doc """
  Looks up an active user by username within a CA instance.
  Returns the user with id and email for password reset flow.
  """
  def get_user_by_username(username, ca_instance_id) do
    case Repo.one(from u in CaUser,
      where: u.username == ^username and u.ca_instance_id == ^ca_instance_id and u.status == "active"
    ) do
      nil -> {:error, :not_found}
      user -> {:ok, user}
    end
  end
```

- [ ] **Step 3: Add `get_user_by_username/1` to RA Engine UserManagement**

Add to `PkiRaEngine.UserManagement` (after `authenticate/2`):

```elixir
  @doc """
  Looks up an active user by username across all active tenants.
  Returns the first match (usernames are unique per tenant).
  """
  def get_user_by_username(username) do
    case Repo.one(from u in RaUser,
      where: u.username == ^username and u.status == "active",
      limit: 1
    ) do
      nil -> {:error, :not_found}
      user -> {:ok, user}
    end
  end
```

- [ ] **Step 4: Commit**

```bash
git add src/pki_platform_engine/lib/pki_platform_engine/admin_management.ex \
        src/pki_platform_engine/lib/pki_platform_engine/platform_admin.ex \
        src/pki_ca_engine/lib/pki_ca_engine/user_management.ex \
        src/pki_ra_engine/lib/pki_ra_engine/user_management.ex
git commit -m "feat: add user lookup and password reset functions for forgot password"
```

---

## Task 4: Add CA/RA engine API endpoints for user lookup by username

**Files:**
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/api/auth_router.ex`
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/api/auth_controller.ex`
- Modify: `src/pki_ra_engine/lib/pki_ra_engine/api/auth_router.ex`
- Modify: `src/pki_ra_engine/lib/pki_ra_engine/api/auth_controller.ex`

These are placed on the **auth router** (public, rate-limited) because the user isn't authenticated yet. The endpoint returns `id` and the real email (the portal needs it to send the code; it masks the email for display).

- [ ] **Step 1: Add route to CA Engine AuthRouter**

In `src/pki_ca_engine/lib/pki_ca_engine/api/auth_router.ex`, add after the `get "/needs-setup"` route (line 22):

```elixir
  get "/user-by-username/:username" do
    PkiCaEngine.Api.AuthController.user_by_username(conn, username)
  end
```

- [ ] **Step 2: Add `user_by_username/2` action to CA Engine AuthController**

Read the existing `src/pki_ca_engine/lib/pki_ca_engine/api/auth_controller.ex` to find where to add. Add this action:

```elixir
  def user_by_username(conn, username) do
    ca_instance_id = conn.query_params["ca_instance_id"] || "default"

    case PkiCaEngine.UserManagement.get_user_by_username(username, ca_instance_id) do
      {:ok, user} ->
        json(conn, 200, %{
          id: user.id,
          email: user.email
        })

      {:error, :not_found} ->
        # Return 200 with nil to prevent user enumeration
        json(conn, 200, %{id: nil, email: nil})
    end
  end
```

- [ ] **Step 3: Add route to RA Engine AuthRouter**

In `src/pki_ra_engine/lib/pki_ra_engine/api/auth_router.ex`, add after the `get "/needs-setup"` route:

```elixir
  get "/user-by-username/:username" do
    PkiRaEngine.Api.AuthController.user_by_username(conn, username)
  end
```

- [ ] **Step 4: Add `user_by_username/2` action to RA Engine AuthController**

Read the existing `src/pki_ra_engine/lib/pki_ra_engine/api/auth_controller.ex` to find where to add. Add this action:

```elixir
  def user_by_username(conn, username) do
    case PkiRaEngine.UserManagement.get_user_by_username(username) do
      {:ok, user} ->
        json(conn, 200, %{
          id: user.id,
          email: user.email,
          tenant_id: user.tenant_id
        })

      {:error, :not_found} ->
        json(conn, 200, %{id: nil, email: nil, tenant_id: nil})
    end
  end
```

- [ ] **Step 5: Commit**

```bash
git add src/pki_ca_engine/lib/pki_ca_engine/api/auth_router.ex \
        src/pki_ca_engine/lib/pki_ca_engine/api/auth_controller.ex \
        src/pki_ra_engine/lib/pki_ra_engine/api/auth_router.ex \
        src/pki_ra_engine/lib/pki_ra_engine/api/auth_controller.ex
git commit -m "feat: add user-by-username API endpoints for password reset"
```

---

## Task 5: Add CA/RA engine client callbacks for user lookup

**Files:**
- Modify: `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client.ex`
- Modify: `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/http.ex`
- Modify: `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/mock.ex`
- Modify: `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/stateful_mock.ex`
- Modify: `src/pki_ra_portal/lib/pki_ra_portal/ra_engine_client.ex`
- Modify: `src/pki_ra_portal/lib/pki_ra_portal/ra_engine_client/http.ex`

- [ ] **Step 1: Add callback to CA engine client behaviour**

In `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client.ex`, add callback (after line 26):

```elixir
  @callback get_user_by_username(String.t()) :: {:ok, map()} | {:error, term()}
```

Add delegate (after line 46):

```elixir
  def get_user_by_username(username), do: impl().get_user_by_username(username)
```

- [ ] **Step 2: Implement HTTP client for CA portal**

In `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/http.ex`, add (in the public auth endpoints section):

```elixir
  @impl true
  def get_user_by_username(username) do
    case get("/api/v1/auth/user-by-username/#{URI.encode(username)}?ca_instance_id=default") do
      {:ok, %{status: 200, body: body}} ->
        {:ok, atomize_keys(body)}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end
```

- [ ] **Step 3: Implement mock clients for CA portal**

In `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/mock.ex`, add:

```elixir
  @impl true
  def get_user_by_username(_username) do
    {:ok, %{id: "mock-user-id", email: "te**@example.com"}}
  end
```

In `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/stateful_mock.ex`, add:

```elixir
  @impl true
  def get_user_by_username(username) do
    GenServer.call(__MODULE__, {:get_user_by_username, username})
  end
```

And handle the call in the GenServer (find the existing `handle_call` pattern and add a matching clause that looks up users by username in the agent state).

- [ ] **Step 4: Add callback to RA engine client behaviour**

In `src/pki_ra_portal/lib/pki_ra_portal/ra_engine_client.ex`, add callback:

```elixir
  @callback get_user_by_username(String.t()) :: {:ok, map()} | {:error, term()}
```

Add delegate:

```elixir
  def get_user_by_username(username), do: impl().get_user_by_username(username)
```

- [ ] **Step 5: Implement HTTP client for RA portal**

In `src/pki_ra_portal/lib/pki_ra_portal/ra_engine_client/http.ex`, add:

```elixir
  @impl true
  def get_user_by_username(username) do
    case get("/api/v1/auth/user-by-username/#{URI.encode(username)}") do
      {:ok, %{status: 200, body: body}} ->
        {:ok, atomize_keys(body)}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end
```

- [ ] **Step 6: Implement mock client for RA portal**

In `src/pki_ra_portal/lib/pki_ra_portal/ra_engine_client/mock.ex`, add:

```elixir
  @impl true
  def get_user_by_username(_username) do
    {:ok, %{id: "mock-user-id", email: "te**@example.com", tenant_id: "mock-tenant"}}
  end
```

- [ ] **Step 7: Commit**

```bash
git add src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client.ex \
        src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/http.ex \
        src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/mock.ex \
        src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/stateful_mock.ex \
        src/pki_ra_portal/lib/pki_ra_portal/ra_engine_client.ex \
        src/pki_ra_portal/lib/pki_ra_portal/ra_engine_client/http.ex
git commit -m "feat: add get_user_by_username to CA/RA engine clients"
```

---

## Task 6: Platform Portal — Forgot Password controller + templates + routes

**Files:**
- Create: `src/pki_platform_portal/lib/pki_platform_portal_web/controllers/forgot_password_controller.ex`
- Create: `src/pki_platform_portal/lib/pki_platform_portal_web/controllers/forgot_password_html.ex`
- Create: `src/pki_platform_portal/lib/pki_platform_portal_web/controllers/forgot_password_html/new.html.heex`
- Create: `src/pki_platform_portal/lib/pki_platform_portal_web/controllers/forgot_password_html/code.html.heex`
- Modify: `src/pki_platform_portal/lib/pki_platform_portal_web/router.ex`
- Modify: `src/pki_platform_portal/lib/pki_platform_portal_web/controllers/session_html/login.html.heex`

- [ ] **Step 1: Create ForgotPasswordController**

```elixir
# src/pki_platform_portal/lib/pki_platform_portal_web/controllers/forgot_password_controller.ex
defmodule PkiPlatformPortalWeb.ForgotPasswordController do
  use PkiPlatformPortalWeb, :controller

  alias PkiPlatformEngine.{AdminManagement, EmailVerification, Mailer, EmailTemplates}

  def new(conn, _params) do
    render(conn, :new, layout: false, error: nil)
  end

  def create(conn, %{"username" => username}) do
    case AdminManagement.get_admin_by_username(username) do
      {:ok, admin} when not is_nil(admin.email) ->
        code = EmailVerification.generate_code(admin.email)
        html = EmailTemplates.password_reset_code(code)
        Mailer.send_email(admin.email, "Password Reset Code", html)

        conn
        |> put_session(:reset_user_id, admin.id)
        |> put_session(:reset_email, admin.email)
        |> render(:code, layout: false, error: nil, masked_email: mask_email(admin.email))

      _ ->
        # Don't reveal whether user exists — show code form with fake masked email
        conn
        |> put_session(:reset_user_id, nil)
        |> put_session(:reset_email, nil)
        |> render(:code, layout: false, error: nil, masked_email: "***@***.com")
    end
  end

  def create(conn, _params) do
    render(conn, :new, layout: false, error: "Username is required.")
  end

  def update(conn, %{"code" => code, "password" => password, "password_confirmation" => confirmation}) do
    reset_email = get_session(conn, :reset_email)
    reset_user_id = get_session(conn, :reset_user_id)

    cond do
      is_nil(reset_user_id) || is_nil(reset_email) ->
        render(conn, :new, layout: false, error: "Invalid reset session. Please start over.")

      String.length(password) < 8 ->
        render(conn, :code, layout: false, error: "Password must be at least 8 characters.", masked_email: mask_email(reset_email))

      password != confirmation ->
        render(conn, :code, layout: false, error: "Passwords do not match.", masked_email: mask_email(reset_email))

      true ->
        case EmailVerification.verify_code(reset_email, code) do
          :ok ->
            case AdminManagement.reset_admin_password(reset_user_id, password) do
              {:ok, _} ->
                conn
                |> delete_session(:reset_user_id)
                |> delete_session(:reset_email)
                |> put_flash(:info, "Password reset successfully. Please sign in.")
                |> redirect(to: "/login")

              {:error, _reason} ->
                render(conn, :code, layout: false, error: "Failed to reset password. Please try again.", masked_email: mask_email(reset_email))
            end

          {:error, :invalid_code} ->
            render(conn, :code, layout: false, error: "Invalid code. Please try again.", masked_email: mask_email(reset_email))

          {:error, :expired} ->
            conn
            |> delete_session(:reset_user_id)
            |> delete_session(:reset_email)
            |> render(:new, layout: false, error: "Code expired. Please start over.")

          {:error, :no_code} ->
            conn
            |> delete_session(:reset_user_id)
            |> delete_session(:reset_email)
            |> render(:new, layout: false, error: "No reset code found. Please start over.")
        end
    end
  end

  def update(conn, _params) do
    render(conn, :code, layout: false, error: "All fields are required.", masked_email: "***")
  end

  defp mask_email(nil), do: "***@***.com"
  defp mask_email(email) do
    case String.split(email, "@") do
      [local, domain] ->
        masked_local = String.slice(local, 0, 2) <> String.duplicate("*", max(String.length(local) - 2, 0))
        masked_local <> "@" <> domain
      _ -> "***@***.com"
    end
  end
end
```

- [ ] **Step 2: Create view module**

```elixir
# src/pki_platform_portal/lib/pki_platform_portal_web/controllers/forgot_password_html.ex
defmodule PkiPlatformPortalWeb.ForgotPasswordHTML do
  use PkiPlatformPortalWeb, :html

  embed_templates "forgot_password_html/*"
end
```

- [ ] **Step 3: Create `new.html.heex` template (username form)**

```heex
<%!-- src/pki_platform_portal/lib/pki_platform_portal_web/controllers/forgot_password_html/new.html.heex --%>
<div class="min-h-screen flex items-center justify-center bg-base-100 px-8 py-12">
  <div class="w-full max-w-sm">
    <div class="mb-8">
      <div class="flex items-center justify-center w-12 h-12 rounded-xl bg-warning mb-4">
        <span class="hero-key text-warning-content text-xl" />
      </div>
      <h1 class="text-2xl font-bold text-base-content">Reset Password</h1>
      <p class="text-sm text-base-content/50 mt-1">Enter your username to receive a reset code.</p>
    </div>

    <%= if @error do %>
      <div class="alert alert-error text-sm mb-4">
        <span class="hero-exclamation-circle text-lg" />
        <span><%= @error %></span>
      </div>
    <% end %>

    <form action="/forgot-password" method="post" class="space-y-4">
      <input type="hidden" name="_csrf_token" value={Plug.CSRFProtection.get_csrf_token()} />

      <div>
        <label for="username" class="block text-xs font-medium text-base-content/60 mb-1">Username</label>
        <input
          type="text"
          name="username"
          id="username"
          required
          autocomplete="username"
          class="input input-bordered input-sm w-full"
          placeholder="Enter your username"
          autofocus
        />
      </div>

      <button type="submit" class="btn btn-primary btn-sm w-full mt-2">
        Send Reset Code
      </button>
    </form>

    <div class="mt-4 text-center">
      <a href="/login" class="text-xs text-primary hover:underline">Back to sign in</a>
    </div>
  </div>
</div>
```

- [ ] **Step 4: Create `code.html.heex` template (code + new password form)**

```heex
<%!-- src/pki_platform_portal/lib/pki_platform_portal_web/controllers/forgot_password_html/code.html.heex --%>
<div class="min-h-screen flex items-center justify-center bg-base-100 px-8 py-12">
  <div class="w-full max-w-sm">
    <div class="mb-8">
      <div class="flex items-center justify-center w-12 h-12 rounded-xl bg-warning mb-4">
        <span class="hero-key text-warning-content text-xl" />
      </div>
      <h1 class="text-2xl font-bold text-base-content">Enter Reset Code</h1>
      <p class="text-sm text-base-content/50 mt-1">
        A 6-digit code was sent to <strong><%= @masked_email %></strong>
      </p>
    </div>

    <%= if @error do %>
      <div class="alert alert-error text-sm mb-4">
        <span class="hero-exclamation-circle text-lg" />
        <span><%= @error %></span>
      </div>
    <% end %>

    <form action="/forgot-password" method="post" class="space-y-4">
      <input type="hidden" name="_method" value="put" />
      <input type="hidden" name="_csrf_token" value={Plug.CSRFProtection.get_csrf_token()} />

      <div>
        <label for="code" class="block text-xs font-medium text-base-content/60 mb-1">Reset Code</label>
        <input
          type="text"
          name="code"
          id="code"
          required
          maxlength="6"
          pattern="[0-9]{6}"
          inputmode="numeric"
          autocomplete="one-time-code"
          class="input input-bordered input-sm w-full tracking-widest text-center font-mono text-lg"
          placeholder="000000"
          autofocus
        />
      </div>

      <div>
        <label for="password" class="block text-xs font-medium text-base-content/60 mb-1">New Password</label>
        <input
          type="password"
          name="password"
          id="password"
          required
          minlength="8"
          autocomplete="new-password"
          class="input input-bordered input-sm w-full"
          placeholder="Enter new password"
        />
      </div>

      <div>
        <label for="password_confirmation" class="block text-xs font-medium text-base-content/60 mb-1">Confirm Password</label>
        <input
          type="password"
          name="password_confirmation"
          id="password_confirmation"
          required
          minlength="8"
          autocomplete="new-password"
          class="input input-bordered input-sm w-full"
          placeholder="Confirm new password"
        />
      </div>

      <button type="submit" class="btn btn-primary btn-sm w-full mt-2">
        Reset Password
      </button>
    </form>

    <div class="mt-4 text-center">
      <a href="/forgot-password" class="text-xs text-primary hover:underline">Start over</a>
    </div>
  </div>
</div>
```

- [ ] **Step 5: Add routes to Platform Portal router**

In `src/pki_platform_portal/lib/pki_platform_portal_web/router.ex`, add to the public scope (after `delete "/logout"` on line 31):

```elixir
    get "/forgot-password", ForgotPasswordController, :new
    post "/forgot-password", ForgotPasswordController, :create
    put "/forgot-password", ForgotPasswordController, :update
```

- [ ] **Step 6: Add "Forgot password?" link to Platform login page**

In `src/pki_platform_portal/lib/pki_platform_portal_web/controllers/session_html/login.html.heex`, add after the submit button (after line 50, before `</.form>`):

```heex
        <div class="mt-3 text-center">
          <a href="/forgot-password" class="text-xs text-primary hover:underline">Forgot password?</a>
        </div>
```

- [ ] **Step 7: Compile and verify no errors**

```bash
cd src/pki_platform_portal && mix compile --warnings-as-errors
```

- [ ] **Step 8: Commit**

```bash
git add src/pki_platform_portal/lib/pki_platform_portal_web/controllers/forgot_password_controller.ex \
        src/pki_platform_portal/lib/pki_platform_portal_web/controllers/forgot_password_html.ex \
        src/pki_platform_portal/lib/pki_platform_portal_web/controllers/forgot_password_html/ \
        src/pki_platform_portal/lib/pki_platform_portal_web/router.ex \
        src/pki_platform_portal/lib/pki_platform_portal_web/controllers/session_html/login.html.heex
git commit -m "feat: add forgot password flow to Platform Admin Portal"
```

---

## Task 7: CA Portal — Forgot Password controller + templates + routes

**Files:**
- Create: `src/pki_ca_portal/lib/pki_ca_portal_web/controllers/forgot_password_controller.ex`
- Create: `src/pki_ca_portal/lib/pki_ca_portal_web/controllers/forgot_password_html.ex`
- Create: `src/pki_ca_portal/lib/pki_ca_portal_web/controllers/forgot_password_html/new.html.heex`
- Create: `src/pki_ca_portal/lib/pki_ca_portal_web/controllers/forgot_password_html/code.html.heex`
- Modify: `src/pki_ca_portal/lib/pki_ca_portal_web/router.ex`
- Modify: `src/pki_ca_portal/lib/pki_ca_portal_web/controllers/session_html/login.html.heex`

- [ ] **Step 1: Create ForgotPasswordController**

```elixir
# src/pki_ca_portal/lib/pki_ca_portal_web/controllers/forgot_password_controller.ex
defmodule PkiCaPortalWeb.ForgotPasswordController do
  use PkiCaPortalWeb, :controller

  alias PkiCaPortal.CaEngineClient
  alias PkiPlatformEngine.{EmailVerification, Mailer, EmailTemplates}

  def new(conn, _params) do
    render(conn, :new, layout: false, error: nil)
  end

  def create(conn, %{"username" => username}) do
    case CaEngineClient.get_user_by_username(username) do
      {:ok, %{id: id, email: email}} when not is_nil(id) and not is_nil(email) ->
        # We have the real email from the engine — need to fetch actual email
        # The API returns masked email. We need the real email for sending.
        # Approach: the engine returns the actual email over the internal API,
        # and the portal sends the code email.
        send_code_and_render(conn, id, email)

      _ ->
        # Don't reveal whether user exists
        conn
        |> put_session(:reset_user_id, nil)
        |> put_session(:reset_email, nil)
        |> render(:code, layout: false, error: nil, masked_email: "***@***.com")
    end
  end

  def create(conn, _params) do
    render(conn, :new, layout: false, error: "Username is required.")
  end

  def update(conn, %{"code" => code, "password" => password, "password_confirmation" => confirmation}) do
    reset_email = get_session(conn, :reset_email)
    reset_user_id = get_session(conn, :reset_user_id)

    cond do
      is_nil(reset_user_id) || is_nil(reset_email) ->
        render(conn, :new, layout: false, error: "Invalid reset session. Please start over.")

      String.length(password) < 8 ->
        render(conn, :code, layout: false, error: "Password must be at least 8 characters.", masked_email: mask_email(reset_email))

      password != confirmation ->
        render(conn, :code, layout: false, error: "Passwords do not match.", masked_email: mask_email(reset_email))

      true ->
        case EmailVerification.verify_code(reset_email, code) do
          :ok ->
            case update_user_password(reset_user_id, password) do
              :ok ->
                conn
                |> delete_session(:reset_user_id)
                |> delete_session(:reset_email)
                |> put_flash(:info, "Password reset successfully. Please sign in.")
                |> redirect(to: "/login")

              {:error, _reason} ->
                render(conn, :code, layout: false, error: "Failed to reset password. Please try again.", masked_email: mask_email(reset_email))
            end

          {:error, :invalid_code} ->
            render(conn, :code, layout: false, error: "Invalid code. Please try again.", masked_email: mask_email(reset_email))

          {:error, :expired} ->
            conn
            |> delete_session(:reset_user_id)
            |> delete_session(:reset_email)
            |> render(:new, layout: false, error: "Code expired. Please start over.")

          {:error, :no_code} ->
            conn
            |> delete_session(:reset_user_id)
            |> delete_session(:reset_email)
            |> render(:new, layout: false, error: "No reset code found. Please start over.")
        end
    end
  end

  def update(conn, _params) do
    render(conn, :code, layout: false, error: "All fields are required.", masked_email: "***")
  end

  defp send_code_and_render(conn, user_id, email) do
    code = EmailVerification.generate_code(email)
    html = EmailTemplates.password_reset_code(code)
    Mailer.send_email(email, "Password Reset Code", html)

    conn
    |> put_session(:reset_user_id, user_id)
    |> put_session(:reset_email, email)
    |> render(:code, layout: false, error: nil, masked_email: mask_email(email))
  end

  defp update_user_password(user_id, new_password) do
    secret =
      Application.get_env(:pki_ca_portal, :internal_api_secret) ||
        System.get_env("INTERNAL_API_SECRET", "")

    base_url =
      Application.get_env(:pki_ca_portal, :ca_engine_url) ||
        "http://127.0.0.1:4001"

    case Req.put("#{base_url}/api/v1/users/#{user_id}/password",
           json: %{password: new_password, must_change_password: false},
           headers: [{"authorization", "Bearer #{secret}"}]
         ) do
      {:ok, %{status: status}} when status in 200..299 -> :ok
      {:ok, %{status: status, body: body}} -> {:error, "API error #{status}: #{inspect(body)}"}
      {:error, reason} -> {:error, reason}
    end
  end

  defp mask_email(nil), do: "***@***.com"
  defp mask_email(email) do
    case String.split(email, "@") do
      [local, domain] ->
        masked_local = String.slice(local, 0, 2) <> String.duplicate("*", max(String.length(local) - 2, 0))
        masked_local <> "@" <> domain
      _ -> "***@***.com"
    end
  end
end
```

- [ ] **Step 2: Create view module**

```elixir
# src/pki_ca_portal/lib/pki_ca_portal_web/controllers/forgot_password_html.ex
defmodule PkiCaPortalWeb.ForgotPasswordHTML do
  use PkiCaPortalWeb, :html

  embed_templates "forgot_password_html/*"
end
```

- [ ] **Step 3: Create `new.html.heex` template**

Same as Platform Portal's template (Task 6 Step 3) but with heading:
- Icon: `hero-shield-check` with `bg-warning`
- Title: "Reset Password"
- Subtitle: "Enter your username to receive a reset code."

```heex
<%!-- src/pki_ca_portal/lib/pki_ca_portal_web/controllers/forgot_password_html/new.html.heex --%>
<div class="min-h-screen flex items-center justify-center bg-base-100 px-8 py-12">
  <div class="w-full max-w-sm">
    <div class="mb-8">
      <div class="flex items-center justify-center w-12 h-12 rounded-xl bg-warning mb-4">
        <span class="hero-key text-warning-content text-xl" />
      </div>
      <h1 class="text-2xl font-bold text-base-content">Reset Password</h1>
      <p class="text-sm text-base-content/50 mt-1">Enter your username to receive a reset code.</p>
    </div>

    <%= if @error do %>
      <div class="alert alert-error text-sm mb-4">
        <span class="hero-exclamation-circle text-lg" />
        <span><%= @error %></span>
      </div>
    <% end %>

    <form action="/forgot-password" method="post" class="space-y-4">
      <input type="hidden" name="_csrf_token" value={Plug.CSRFProtection.get_csrf_token()} />

      <div>
        <label for="username" class="block text-xs font-medium text-base-content/60 mb-1">Username</label>
        <input
          type="text"
          name="username"
          id="username"
          required
          autocomplete="username"
          class="input input-bordered input-sm w-full"
          placeholder="Enter your username"
          autofocus
        />
      </div>

      <button type="submit" class="btn btn-primary btn-sm w-full mt-2">
        Send Reset Code
      </button>
    </form>

    <div class="mt-4 text-center">
      <a href="/login" class="text-xs text-primary hover:underline">Back to sign in</a>
    </div>
  </div>
</div>
```

- [ ] **Step 4: Create `code.html.heex` template**

Same as Platform Portal's template (Task 6 Step 4). Copy verbatim.

```heex
<%!-- src/pki_ca_portal/lib/pki_ca_portal_web/controllers/forgot_password_html/code.html.heex --%>
<div class="min-h-screen flex items-center justify-center bg-base-100 px-8 py-12">
  <div class="w-full max-w-sm">
    <div class="mb-8">
      <div class="flex items-center justify-center w-12 h-12 rounded-xl bg-warning mb-4">
        <span class="hero-key text-warning-content text-xl" />
      </div>
      <h1 class="text-2xl font-bold text-base-content">Enter Reset Code</h1>
      <p class="text-sm text-base-content/50 mt-1">
        A 6-digit code was sent to <strong><%= @masked_email %></strong>
      </p>
    </div>

    <%= if @error do %>
      <div class="alert alert-error text-sm mb-4">
        <span class="hero-exclamation-circle text-lg" />
        <span><%= @error %></span>
      </div>
    <% end %>

    <form action="/forgot-password" method="post" class="space-y-4">
      <input type="hidden" name="_method" value="put" />
      <input type="hidden" name="_csrf_token" value={Plug.CSRFProtection.get_csrf_token()} />

      <div>
        <label for="code" class="block text-xs font-medium text-base-content/60 mb-1">Reset Code</label>
        <input
          type="text"
          name="code"
          id="code"
          required
          maxlength="6"
          pattern="[0-9]{6}"
          inputmode="numeric"
          autocomplete="one-time-code"
          class="input input-bordered input-sm w-full tracking-widest text-center font-mono text-lg"
          placeholder="000000"
          autofocus
        />
      </div>

      <div>
        <label for="password" class="block text-xs font-medium text-base-content/60 mb-1">New Password</label>
        <input
          type="password"
          name="password"
          id="password"
          required
          minlength="8"
          autocomplete="new-password"
          class="input input-bordered input-sm w-full"
          placeholder="Enter new password"
        />
      </div>

      <div>
        <label for="password_confirmation" class="block text-xs font-medium text-base-content/60 mb-1">Confirm Password</label>
        <input
          type="password"
          name="password_confirmation"
          id="password_confirmation"
          required
          minlength="8"
          autocomplete="new-password"
          class="input input-bordered input-sm w-full"
          placeholder="Confirm new password"
        />
      </div>

      <button type="submit" class="btn btn-primary btn-sm w-full mt-2">
        Reset Password
      </button>
    </form>

    <div class="mt-4 text-center">
      <a href="/forgot-password" class="text-xs text-primary hover:underline">Start over</a>
    </div>
  </div>
</div>
```

- [ ] **Step 5: Add routes to CA Portal router**

In `src/pki_ca_portal/lib/pki_ca_portal_web/router.ex`, add to the public scope (after `put "/change-password"` on line 31):

```elixir
    get "/forgot-password", ForgotPasswordController, :new
    post "/forgot-password", ForgotPasswordController, :create
    put "/forgot-password", ForgotPasswordController, :update
```

- [ ] **Step 6: Add "Forgot password?" link to CA login page**

In `src/pki_ca_portal/lib/pki_ca_portal_web/controllers/session_html/login.html.heex`, add after the submit button (after line 50, before `</.form>`):

```heex
        <div class="mt-3 text-center">
          <a href="/forgot-password" class="text-xs text-primary hover:underline">Forgot password?</a>
        </div>
```

- [ ] **Step 7: Compile and verify**

```bash
cd src/pki_ca_portal && mix compile --warnings-as-errors
```

- [ ] **Step 8: Commit**

```bash
git add src/pki_ca_portal/lib/pki_ca_portal_web/controllers/forgot_password_controller.ex \
        src/pki_ca_portal/lib/pki_ca_portal_web/controllers/forgot_password_html.ex \
        src/pki_ca_portal/lib/pki_ca_portal_web/controllers/forgot_password_html/ \
        src/pki_ca_portal/lib/pki_ca_portal_web/router.ex \
        src/pki_ca_portal/lib/pki_ca_portal_web/controllers/session_html/login.html.heex
git commit -m "feat: add forgot password flow to CA Portal"
```

---

## Task 8: RA Portal — Forgot Password controller + templates + routes

**Files:**
- Create: `src/pki_ra_portal/lib/pki_ra_portal_web/controllers/forgot_password_controller.ex`
- Create: `src/pki_ra_portal/lib/pki_ra_portal_web/controllers/forgot_password_html.ex`
- Create: `src/pki_ra_portal/lib/pki_ra_portal_web/controllers/forgot_password_html/new.html.heex`
- Create: `src/pki_ra_portal/lib/pki_ra_portal_web/controllers/forgot_password_html/code.html.heex`
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/router.ex`
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/controllers/session_html/login.html.heex`

- [ ] **Step 1: Create ForgotPasswordController**

Same pattern as CA Portal (Task 7 Step 1) but using `RaEngineClient` and RA engine URL:

```elixir
# src/pki_ra_portal/lib/pki_ra_portal_web/controllers/forgot_password_controller.ex
defmodule PkiRaPortalWeb.ForgotPasswordController do
  use PkiRaPortalWeb, :controller

  alias PkiRaPortal.RaEngineClient
  alias PkiPlatformEngine.{EmailVerification, Mailer, EmailTemplates}

  def new(conn, _params) do
    render(conn, :new, layout: false, error: nil)
  end

  def create(conn, %{"username" => username}) do
    case RaEngineClient.get_user_by_username(username) do
      {:ok, %{id: id, email: email}} when not is_nil(id) and not is_nil(email) ->
        send_code_and_render(conn, id, email)

      _ ->
        conn
        |> put_session(:reset_user_id, nil)
        |> put_session(:reset_email, nil)
        |> render(:code, layout: false, error: nil, masked_email: "***@***.com")
    end
  end

  def create(conn, _params) do
    render(conn, :new, layout: false, error: "Username is required.")
  end

  def update(conn, %{"code" => code, "password" => password, "password_confirmation" => confirmation}) do
    reset_email = get_session(conn, :reset_email)
    reset_user_id = get_session(conn, :reset_user_id)

    cond do
      is_nil(reset_user_id) || is_nil(reset_email) ->
        render(conn, :new, layout: false, error: "Invalid reset session. Please start over.")

      String.length(password) < 8 ->
        render(conn, :code, layout: false, error: "Password must be at least 8 characters.", masked_email: mask_email(reset_email))

      password != confirmation ->
        render(conn, :code, layout: false, error: "Passwords do not match.", masked_email: mask_email(reset_email))

      true ->
        case EmailVerification.verify_code(reset_email, code) do
          :ok ->
            case update_user_password(reset_user_id, password) do
              :ok ->
                conn
                |> delete_session(:reset_user_id)
                |> delete_session(:reset_email)
                |> put_flash(:info, "Password reset successfully. Please sign in.")
                |> redirect(to: "/login")

              {:error, _reason} ->
                render(conn, :code, layout: false, error: "Failed to reset password. Please try again.", masked_email: mask_email(reset_email))
            end

          {:error, :invalid_code} ->
            render(conn, :code, layout: false, error: "Invalid code. Please try again.", masked_email: mask_email(reset_email))

          {:error, :expired} ->
            conn
            |> delete_session(:reset_user_id)
            |> delete_session(:reset_email)
            |> render(:new, layout: false, error: "Code expired. Please start over.")

          {:error, :no_code} ->
            conn
            |> delete_session(:reset_user_id)
            |> delete_session(:reset_email)
            |> render(:new, layout: false, error: "No reset code found. Please start over.")
        end
    end
  end

  def update(conn, _params) do
    render(conn, :code, layout: false, error: "All fields are required.", masked_email: "***")
  end

  defp send_code_and_render(conn, user_id, email) do
    code = EmailVerification.generate_code(email)
    html = EmailTemplates.password_reset_code(code)
    Mailer.send_email(email, "Password Reset Code", html)

    conn
    |> put_session(:reset_user_id, user_id)
    |> put_session(:reset_email, email)
    |> render(:code, layout: false, error: nil, masked_email: mask_email(email))
  end

  defp update_user_password(user_id, new_password) do
    secret =
      Application.get_env(:pki_ra_portal, :internal_api_secret) ||
        System.get_env("INTERNAL_API_SECRET", "")

    base_url =
      Application.get_env(:pki_ra_portal, :ra_engine_url) ||
        "http://127.0.0.1:4003"

    case Req.put("#{base_url}/api/v1/users/#{user_id}/password",
           json: %{password: new_password, must_change_password: false},
           headers: [{"authorization", "Bearer #{secret}"}]
         ) do
      {:ok, %{status: status}} when status in 200..299 -> :ok
      {:ok, %{status: status, body: body}} -> {:error, "API error #{status}: #{inspect(body)}"}
      {:error, reason} -> {:error, reason}
    end
  end

  defp mask_email(nil), do: "***@***.com"
  defp mask_email(email) do
    case String.split(email, "@") do
      [local, domain] ->
        masked_local = String.slice(local, 0, 2) <> String.duplicate("*", max(String.length(local) - 2, 0))
        masked_local <> "@" <> domain
      _ -> "***@***.com"
    end
  end
end
```

- [ ] **Step 2: Create view module**

```elixir
# src/pki_ra_portal/lib/pki_ra_portal_web/controllers/forgot_password_html.ex
defmodule PkiRaPortalWeb.ForgotPasswordHTML do
  use PkiRaPortalWeb, :html

  embed_templates "forgot_password_html/*"
end
```

- [ ] **Step 3: Create `new.html.heex` template**

Identical to CA Portal (Task 7 Step 3). Copy verbatim.

- [ ] **Step 4: Create `code.html.heex` template**

Identical to CA Portal (Task 7 Step 4). Copy verbatim.

- [ ] **Step 5: Add routes to RA Portal router**

In `src/pki_ra_portal/lib/pki_ra_portal_web/router.ex`, add to the public scope (after `put "/change-password"`):

```elixir
    get "/forgot-password", ForgotPasswordController, :new
    post "/forgot-password", ForgotPasswordController, :create
    put "/forgot-password", ForgotPasswordController, :update
```

- [ ] **Step 6: Add "Forgot password?" link to RA login page**

In `src/pki_ra_portal/lib/pki_ra_portal_web/controllers/session_html/login.html.heex`, add after the submit button (after line 48, before `</.form>`):

```heex
        <div class="mt-3 text-center">
          <a href="/forgot-password" class="text-xs text-primary hover:underline">Forgot password?</a>
        </div>
```

- [ ] **Step 7: Compile and verify**

```bash
cd src/pki_ra_portal && mix compile --warnings-as-errors
```

- [ ] **Step 8: Commit**

```bash
git add src/pki_ra_portal/lib/pki_ra_portal_web/controllers/forgot_password_controller.ex \
        src/pki_ra_portal/lib/pki_ra_portal_web/controllers/forgot_password_html.ex \
        src/pki_ra_portal/lib/pki_ra_portal_web/controllers/forgot_password_html/ \
        src/pki_ra_portal/lib/pki_ra_portal_web/router.ex \
        src/pki_ra_portal/lib/pki_ra_portal_web/controllers/session_html/login.html.heex
git commit -m "feat: add forgot password flow to RA Portal"
```

---

## Task 9: Smoke test all 3 portals

- [ ] **Step 1: Start all services**

```bash
cd src/pki_platform_engine && mix ecto.migrate
cd src/pki_ca_engine && mix ecto.migrate
cd src/pki_ra_engine && mix ecto.migrate
```

Start the umbrella or each app individually.

- [ ] **Step 2: Verify Platform Portal**

1. Navigate to `http://localhost:4000/login`
2. Confirm "Forgot password?" link is visible below the Sign In button
3. Click it — should navigate to `/forgot-password`
4. Enter a username — should show the code entry form
5. Check server logs for the email send (or Resend dashboard)

- [ ] **Step 3: Verify CA Portal**

1. Navigate to `http://localhost:4002/login`
2. Confirm "Forgot password?" link is visible
3. Click and test the flow

- [ ] **Step 4: Verify RA Portal**

1. Navigate to `http://localhost:4004/login`
2. Confirm "Forgot password?" link is visible
3. Click and test the flow

- [ ] **Step 5: Final commit (if any fixes needed)**

```bash
git add -A
git commit -m "fix: address smoke test issues in forgot password flow"
```
