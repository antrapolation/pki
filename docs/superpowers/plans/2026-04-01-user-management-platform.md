# User Management via Platform Auth — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix CA/RA user management to go through platform-level auth (UserProfile + UserTenantRole), add email invitation flow, and comprehensive audit logging.

**Architecture:** All user CRUD moves to `PlatformAuth` in the platform engine. New `PlatformAudit` module + `platform_audit_events` table for logging. CA/RA portals' UsersLive and AuditLogLive are updated to use platform-level data. Email invitations use existing `Mailer` + `EmailTemplates`.

**Tech Stack:** Phoenix LiveView, Ecto, Argon2, Resend API (email), daisyUI/Tailwind CSS

---

## File Map

### Platform Engine (backend)
- Create: `src/pki_platform_engine/lib/pki_platform_engine/platform_audit.ex` — audit logging module
- Create: `src/pki_platform_engine/lib/pki_platform_engine/platform_audit_event.ex` — audit event schema
- Create: `src/pki_platform_engine/priv/platform_repo/migrations/20260401000001_create_platform_audit_events.exs` — migration
- Modify: `src/pki_platform_engine/lib/pki_platform_engine/platform_auth.ex` — add user CRUD, password reset, list users
- Modify: `src/pki_platform_engine/lib/pki_platform_engine/email_templates.ex` — add user invitation template

### CA Portal
- Modify: `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client.ex` — add new callbacks
- Modify: `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/direct.ex` — implement via PlatformAuth
- Modify: `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/mock.ex` — update mock
- Modify: `src/pki_ca_portal/lib/pki_ca_portal_web/live/users_live.ex` — new form + actions
- Modify: `src/pki_ca_portal/lib/pki_ca_portal_web/live/audit_log_live.ex` — add category filter
- Modify: `src/pki_ca_portal/lib/pki_ca_portal_web/live/profile_live.ex` — add audit logging
- Modify: `src/pki_ca_portal/lib/pki_ca_portal_web/controllers/session_controller.ex` — add audit logging

### RA Portal
- Modify: `src/pki_ra_portal/lib/pki_ra_portal/ra_engine_client.ex` — add new callbacks
- Modify: `src/pki_ra_portal/lib/pki_ra_portal/ra_engine_client/direct.ex` — implement via PlatformAuth
- Modify: `src/pki_ra_portal/lib/pki_ra_portal/ra_engine_client/mock.ex` — update mock
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/live/users_live.ex` — new form + actions
- Create: `src/pki_ra_portal/lib/pki_ra_portal_web/live/audit_log_live.ex` — new audit log page
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/router.ex` — add /audit-log route
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/components/layouts.ex` — add Audit Log sidebar link
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/live/profile_live.ex` — add audit logging
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/controllers/session_controller.ex` — add audit logging

---

## Task 1: Platform Audit Schema + Migration

**Files:**
- Create: `src/pki_platform_engine/lib/pki_platform_engine/platform_audit_event.ex`
- Create: `src/pki_platform_engine/priv/platform_repo/migrations/20260401000001_create_platform_audit_events.exs`

- [ ] **Step 1: Create the PlatformAuditEvent schema**

Create `src/pki_platform_engine/lib/pki_platform_engine/platform_audit_event.ex`:

```elixir
defmodule PkiPlatformEngine.PlatformAuditEvent do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  schema "platform_audit_events" do
    field :timestamp, :utc_datetime_usec
    field :actor_id, :binary_id
    field :actor_username, :string
    field :action, :string
    field :target_type, :string
    field :target_id, :binary_id
    field :tenant_id, :binary_id
    field :portal, :string
    field :details, :map, default: %{}

    timestamps(updated_at: false)
  end

  @actions ~w(login login_failed user_created user_suspended user_activated user_deleted password_reset password_changed profile_updated)

  def changeset(event, attrs) do
    event
    |> cast(attrs, [:timestamp, :actor_id, :actor_username, :action, :target_type, :target_id, :tenant_id, :portal, :details])
    |> validate_required([:timestamp, :action])
    |> validate_inclusion(:action, @actions)
    |> maybe_generate_id()
  end

  defp maybe_generate_id(changeset) do
    if get_field(changeset, :id) do
      changeset
    else
      put_change(changeset, :id, Uniq.UUID.uuid7())
    end
  end
end
```

- [ ] **Step 2: Create the migration**

Create `src/pki_platform_engine/priv/platform_repo/migrations/20260401000001_create_platform_audit_events.exs`:

```elixir
defmodule PkiPlatformEngine.PlatformRepo.Migrations.CreatePlatformAuditEvents do
  use Ecto.Migration

  def change do
    create table(:platform_audit_events, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :timestamp, :utc_datetime_usec, null: false
      add :actor_id, :binary_id
      add :actor_username, :string
      add :action, :string, null: false
      add :target_type, :string
      add :target_id, :binary_id
      add :tenant_id, references(:tenants, type: :binary_id, on_delete: :nilify_all)
      add :portal, :string
      add :details, :map, default: %{}

      timestamps(updated_at: false)
    end

    create index(:platform_audit_events, [:tenant_id])
    create index(:platform_audit_events, [:action])
    create index(:platform_audit_events, [:actor_id])
    create index(:platform_audit_events, [:timestamp])
    create index(:platform_audit_events, [:tenant_id, :portal])
  end
end
```

- [ ] **Step 3: Run the migration**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_platform_engine && mix ecto.migrate
```

- [ ] **Step 4: Verify compilation**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_platform_engine && mix compile
```

- [ ] **Step 5: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki && git add src/pki_platform_engine/lib/pki_platform_engine/platform_audit_event.ex src/pki_platform_engine/priv/platform_repo/migrations/20260401000001_create_platform_audit_events.exs && git commit -m "feat(platform): add platform_audit_events schema and migration

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: PlatformAudit Module

**Files:**
- Create: `src/pki_platform_engine/lib/pki_platform_engine/platform_audit.ex`

- [ ] **Step 1: Create the PlatformAudit module**

Create `src/pki_platform_engine/lib/pki_platform_engine/platform_audit.ex`:

```elixir
defmodule PkiPlatformEngine.PlatformAudit do
  @moduledoc """
  Audit logging for platform-level operations: authentication, user management, profile changes.
  Writes to the platform_audit_events table in the platform DB.
  """

  import Ecto.Query
  alias PkiPlatformEngine.{PlatformRepo, PlatformAuditEvent}

  @doc """
  Log an audit event.

  ## Examples

      PlatformAudit.log("user_created", %{
        actor_id: admin.id,
        actor_username: admin.username,
        target_type: "user_profile",
        target_id: new_user.id,
        tenant_id: tenant_id,
        portal: "ca",
        details: %{username: "newuser", role: "ca_admin"}
      })
  """
  def log(action, attrs \\ %{}) do
    %PlatformAuditEvent{}
    |> PlatformAuditEvent.changeset(
      Map.merge(attrs, %{
        action: action,
        timestamp: DateTime.utc_now()
      })
    )
    |> PlatformRepo.insert()
  end

  @doc """
  Query audit events with filters.

  ## Filters
    * `:tenant_id` — filter by tenant
    * `:portal` — filter by portal ("ca", "ra", "admin")
    * `:action` — filter by action
    * `:actor_username` — filter by actor (partial match)
    * `:date_from` — filter from date (ISO 8601 string or Date)
    * `:date_to` — filter to date (ISO 8601 string or Date)
    * `:limit` — max results (default 200)
  """
  def list_events(filters \\ []) do
    limit = Keyword.get(filters, :limit, 200)

    query =
      from(e in PlatformAuditEvent,
        order_by: [desc: e.timestamp],
        limit: ^limit
      )

    query = Enum.reduce(filters, query, fn
      {:tenant_id, tid}, q when is_binary(tid) and tid != "" ->
        from(e in q, where: e.tenant_id == ^tid)

      {:portal, portal}, q when is_binary(portal) and portal != "" ->
        from(e in q, where: e.portal == ^portal)

      {:action, action}, q when is_binary(action) and action != "" ->
        from(e in q, where: e.action == ^action)

      {:actor_username, actor}, q when is_binary(actor) and actor != "" ->
        from(e in q, where: ilike(e.actor_username, ^"%#{actor}%"))

      {:date_from, date_str}, q when is_binary(date_str) and date_str != "" ->
        case Date.from_iso8601(date_str) do
          {:ok, date} ->
            dt = DateTime.new!(date, ~T[00:00:00], "Etc/UTC")
            from(e in q, where: e.timestamp >= ^dt)
          _ -> q
        end

      {:date_to, date_str}, q when is_binary(date_str) and date_str != "" ->
        case Date.from_iso8601(date_str) do
          {:ok, date} ->
            dt = DateTime.new!(date, ~T[23:59:59], "Etc/UTC")
            from(e in q, where: e.timestamp <= ^dt)
          _ -> q
        end

      _, q -> q
    end)

    PlatformRepo.all(query)
  end
end
```

- [ ] **Step 2: Verify compilation**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_platform_engine && mix compile
```

- [ ] **Step 3: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki && git add src/pki_platform_engine/lib/pki_platform_engine/platform_audit.ex && git commit -m "feat(platform): add PlatformAudit module for audit event logging and querying

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: PlatformAuth — User CRUD Functions

**Files:**
- Modify: `src/pki_platform_engine/lib/pki_platform_engine/platform_auth.ex`
- Modify: `src/pki_platform_engine/lib/pki_platform_engine/email_templates.ex`

- [ ] **Step 1: Add user invitation email template**

In `src/pki_platform_engine/lib/pki_platform_engine/email_templates.ex`, add after the `single_admin_credential` function (before `password_reset_code`):

```elixir
  def user_invitation(tenant_name, role_label, portal_url, username, password) do
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

      <p style="font-size: 15px; margin-bottom: 24px;">You have been invited as <strong>#{role_label}</strong> for tenant <strong>#{tenant_name}</strong>.</p>

      <div style="background: #fef3c7; border: 1px solid #f59e0b; border-radius: 8px; padding: 12px 16px; margin-bottom: 24px;">
        <p style="font-size: 13px; color: #92400e; margin: 0; font-weight: 600;">These credentials expire in 24 hours. Please log in and change your password immediately.</p>
      </div>

      <div style="background: #f8f9fa; border-radius: 12px; padding: 24px; margin-bottom: 24px;">
        <h2 style="font-size: 14px; font-weight: 600; color: #661ae6; margin: 0 0 12px; text-transform: uppercase; letter-spacing: 1px;">Your Credentials</h2>
        <table style="width: 100%; font-size: 14px;">
          <tr><td style="color: #6b7280; padding: 4px 0; width: 100px;">Portal:</td><td><a href="#{portal_url}" style="color: #661ae6;">#{portal_url}</a></td></tr>
          <tr><td style="color: #6b7280; padding: 4px 0;">Username:</td><td style="font-family: monospace; font-weight: 600;">#{username}</td></tr>
          <tr><td style="color: #6b7280; padding: 4px 0;">Password:</td><td style="font-family: monospace; font-weight: 600;">#{password}</td></tr>
        </table>
      </div>

      <div style="font-size: 13px; color: #6b7280;">
        <p><strong>Instructions:</strong></p>
        <ol style="padding-left: 20px;">
          <li>Click the portal link above</li>
          <li>Log in with the provided username and password</li>
          <li>You will be prompted to change your password immediately</li>
        </ol>
      </div>

      <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 24px 0;" />
      <p style="font-size: 12px; color: #9ca3af; text-align: center;">This is an automated message from PQC PKI Platform. Do not reply to this email.</p>
    </body>
    </html>
    """
  end
```

- [ ] **Step 2: Add user CRUD functions to PlatformAuth**

In `src/pki_platform_engine/lib/pki_platform_engine/platform_auth.ex`, add these functions after the existing `get_by_username/1` function:

```elixir
  @doc "List users for a specific tenant and portal with their roles."
  def list_users_for_portal(tenant_id, portal) do
    query = from r in UserTenantRole,
      where: r.tenant_id == ^tenant_id and r.portal == ^portal,
      join: u in UserProfile, on: u.id == r.user_profile_id,
      select: %{
        id: u.id,
        role_id: r.id,
        username: u.username,
        display_name: u.display_name,
        email: u.email,
        role: r.role,
        status: r.status,
        inserted_at: r.inserted_at
      },
      order_by: [asc: r.inserted_at]

    PlatformRepo.all(query)
  end

  @doc """
  Create a user for a portal with email invitation.

  Generates a temporary password, creates UserProfile + UserTenantRole,
  and sends an invitation email.

  ## Attrs
    * `:username` — required
    * `:display_name` — required
    * `:email` — required
    * `:role` — required (e.g., "ca_admin", "key_manager", "ra_officer")

  ## Opts
    * `:portal_url` — URL for the portal (included in email)
    * `:tenant_name` — tenant display name (included in email)
  """
  def create_user_for_portal(tenant_id, portal, attrs, opts \\ []) do
    temp_password = generate_temp_password()
    expires_at = DateTime.add(DateTime.utc_now(), 24 * 3600, :second)

    PlatformRepo.transaction(fn ->
      # Create or find user profile
      user_attrs = %{
        username: attrs[:username] || attrs["username"],
        display_name: attrs[:display_name] || attrs["display_name"],
        email: attrs[:email] || attrs["email"],
        password: temp_password,
        must_change_password: true,
        credential_expires_at: expires_at
      }

      case create_user_profile(user_attrs) do
        {:ok, user} ->
          role = attrs[:role] || attrs["role"]

          case assign_tenant_role(user.id, tenant_id, %{role: role, portal: portal}) do
            {:ok, _role} ->
              # Send invitation email
              send_invitation_email(user, role, portal, temp_password, opts)
              user

            {:error, reason} ->
              PlatformRepo.rollback(reason)
          end

        {:error, changeset} ->
          PlatformRepo.rollback(changeset)
      end
    end)
  end

  @doc "Suspend a user's tenant role (prevents login to that portal)."
  def suspend_user_role(role_id) do
    case PlatformRepo.get(UserTenantRole, role_id) do
      nil -> {:error, :not_found}
      role -> role |> UserTenantRole.changeset(%{status: "suspended"}) |> PlatformRepo.update()
    end
  end

  @doc "Activate a user's tenant role."
  def activate_user_role(role_id) do
    case PlatformRepo.get(UserTenantRole, role_id) do
      nil -> {:error, :not_found}
      role -> role |> UserTenantRole.changeset(%{status: "active"}) |> PlatformRepo.update()
    end
  end

  @doc "Delete a user's tenant role (removes access to that portal for that tenant)."
  def delete_user_role(role_id) do
    case PlatformRepo.get(UserTenantRole, role_id) do
      nil -> {:error, :not_found}
      role -> PlatformRepo.delete(role)
    end
  end

  @doc "Reset a user's password and send new credentials via email."
  def reset_user_password(user_profile_id, portal, opts \\ []) do
    temp_password = generate_temp_password()
    expires_at = DateTime.add(DateTime.utc_now(), 24 * 3600, :second)

    case PlatformRepo.get(UserProfile, user_profile_id) do
      nil -> {:error, :not_found}
      user ->
        case user |> UserProfile.password_changeset(%{
          password: temp_password,
          must_change_password: true
        }) |> Ecto.Changeset.put_change(:credential_expires_at, expires_at) |> PlatformRepo.update() do
          {:ok, updated} ->
            role_label = Keyword.get(opts, :role_label, portal)
            send_password_reset_email(updated, role_label, portal, temp_password, opts)
            {:ok, updated}

          {:error, _} = err -> err
        end
    end
  end

  @doc "Get a user profile by ID."
  def get_user_profile(id) do
    case PlatformRepo.get(UserProfile, id) do
      nil -> {:error, :not_found}
      user -> {:ok, user}
    end
  end

  defp generate_temp_password do
    :crypto.strong_rand_bytes(12) |> Base.encode64(padding: false) |> binary_part(0, 16)
  end

  defp send_invitation_email(user, role, portal, password, opts) do
    portal_url = Keyword.get(opts, :portal_url, "")
    tenant_name = Keyword.get(opts, :tenant_name, "")
    role_label = format_role_label(role, portal)

    html = PkiPlatformEngine.EmailTemplates.user_invitation(tenant_name, role_label, portal_url, user.username, password)
    PkiPlatformEngine.Mailer.send_email(user.email, "You've been invited to #{tenant_name} — #{role_label}", html)
  end

  defp send_password_reset_email(user, role_label, _portal, password, opts) do
    portal_url = Keyword.get(opts, :portal_url, "")
    tenant_name = Keyword.get(opts, :tenant_name, "")

    html = PkiPlatformEngine.EmailTemplates.single_admin_credential(tenant_name, role_label, portal_url, user.username, password)
    PkiPlatformEngine.Mailer.send_email(user.email, "Your password has been reset — #{tenant_name}", html)
  end

  defp format_role_label(role, portal) do
    case {portal, role} do
      {"ca", "ca_admin"} -> "CA Administrator"
      {"ca", "key_manager"} -> "Key Manager"
      {"ca", "auditor"} -> "Auditor"
      {"ra", "ra_admin"} -> "RA Administrator"
      {"ra", "ra_officer"} -> "RA Officer"
      {"ra", "auditor"} -> "Auditor"
      {_, role} -> role
    end
  end
```

- [ ] **Step 3: Verify compilation**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_platform_engine && mix compile
```

- [ ] **Step 4: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki && git add src/pki_platform_engine/lib/pki_platform_engine/platform_auth.ex src/pki_platform_engine/lib/pki_platform_engine/email_templates.ex && git commit -m "feat(platform): add user CRUD, password reset, and email invitation to PlatformAuth

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: CA Portal — Engine Client Updates

**Files:**
- Modify: `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client.ex`
- Modify: `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/direct.ex`
- Modify: `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/mock.ex`

- [ ] **Step 1: Add new callbacks to CaEngineClient behaviour**

In `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client.ex`, add after the existing callbacks (after `@callback reset_password`):

```elixir
  @callback list_portal_users(opts()) :: {:ok, [map()]} | {:error, term()}
  @callback create_portal_user(map(), opts()) :: {:ok, map()} | {:error, term()}
  @callback suspend_user_role(String.t(), opts()) :: {:ok, map()} | {:error, term()}
  @callback activate_user_role(String.t(), opts()) :: {:ok, map()} | {:error, term()}
  @callback delete_user_role(String.t(), opts()) :: {:ok, map()} | {:error, term()}
  @callback reset_user_password(String.t(), opts()) :: {:ok, map()} | {:error, term()}
  @callback list_audit_events(keyword(), opts()) :: {:ok, [map()]} | {:error, term()}
```

And add delegators after the existing ones:

```elixir
  def list_portal_users(opts \\ []), do: impl().list_portal_users(opts)
  def create_portal_user(attrs, opts \\ []), do: impl().create_portal_user(attrs, opts)
  def suspend_user_role(role_id, opts \\ []), do: impl().suspend_user_role(role_id, opts)
  def activate_user_role(role_id, opts \\ []), do: impl().activate_user_role(role_id, opts)
  def delete_user_role(role_id, opts \\ []), do: impl().delete_user_role(role_id, opts)
  def reset_user_password(user_id, opts \\ []), do: impl().reset_user_password(user_id, opts)
  def list_audit_events(filters, opts \\ []), do: impl().list_audit_events(filters, opts)
```

- [ ] **Step 2: Implement in Direct client**

In `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/direct.ex`, add before the `# --- Struct to map` section (or before existing user management section):

```elixir
  # ---------------------------------------------------------------------------
  # Platform-level User Management
  # ---------------------------------------------------------------------------

  @impl true
  def list_portal_users(opts \\ []) do
    tenant_id = opts[:tenant_id]
    {:ok, PkiPlatformEngine.PlatformAuth.list_users_for_portal(tenant_id, "ca")}
  end

  @impl true
  def create_portal_user(attrs, opts \\ []) do
    tenant_id = opts[:tenant_id]
    portal_url = Application.get_env(:pki_ca_portal, :portal_url, "")
    tenant_name = get_tenant_name(tenant_id)

    case PkiPlatformEngine.PlatformAuth.create_user_for_portal(tenant_id, "ca", attrs,
      portal_url: portal_url,
      tenant_name: tenant_name
    ) do
      {:ok, user} ->
        PkiPlatformEngine.PlatformAudit.log("user_created", %{
          actor_id: opts[:actor_id],
          actor_username: opts[:actor_username],
          target_type: "user_profile",
          target_id: user.id,
          tenant_id: tenant_id,
          portal: "ca",
          details: %{username: user.username, role: attrs[:role] || attrs["role"]}
        })
        {:ok, %{id: user.id, username: user.username, display_name: user.display_name, email: user.email}}

      {:error, %Ecto.Changeset{} = cs} -> {:error, {:validation_error, changeset_errors(cs)}}
      {:error, reason} -> {:error, reason}
    end
  end

  @impl true
  def suspend_user_role(role_id, opts \\ []) do
    case PkiPlatformEngine.PlatformAuth.suspend_user_role(role_id) do
      {:ok, role} ->
        PkiPlatformEngine.PlatformAudit.log("user_suspended", %{
          actor_id: opts[:actor_id],
          actor_username: opts[:actor_username],
          target_type: "user_tenant_role",
          target_id: role_id,
          tenant_id: opts[:tenant_id],
          portal: "ca"
        })
        {:ok, %{id: role.id, status: role.status}}

      {:error, _} = err -> err
    end
  end

  @impl true
  def activate_user_role(role_id, opts \\ []) do
    case PkiPlatformEngine.PlatformAuth.activate_user_role(role_id) do
      {:ok, role} ->
        PkiPlatformEngine.PlatformAudit.log("user_activated", %{
          actor_id: opts[:actor_id],
          actor_username: opts[:actor_username],
          target_type: "user_tenant_role",
          target_id: role_id,
          tenant_id: opts[:tenant_id],
          portal: "ca"
        })
        {:ok, %{id: role.id, status: role.status}}

      {:error, _} = err -> err
    end
  end

  @impl true
  def delete_user_role(role_id, opts \\ []) do
    case PkiPlatformEngine.PlatformAuth.delete_user_role(role_id) do
      {:ok, _} ->
        PkiPlatformEngine.PlatformAudit.log("user_deleted", %{
          actor_id: opts[:actor_id],
          actor_username: opts[:actor_username],
          target_type: "user_tenant_role",
          target_id: role_id,
          tenant_id: opts[:tenant_id],
          portal: "ca"
        })
        {:ok, %{id: role_id}}

      {:error, _} = err -> err
    end
  end

  @impl true
  def reset_user_password(user_id, opts \\ []) do
    tenant_id = opts[:tenant_id]
    portal_url = Application.get_env(:pki_ca_portal, :portal_url, "")
    tenant_name = get_tenant_name(tenant_id)

    case PkiPlatformEngine.PlatformAuth.reset_user_password(user_id, "ca",
      portal_url: portal_url,
      tenant_name: tenant_name
    ) do
      {:ok, _} ->
        PkiPlatformEngine.PlatformAudit.log("password_reset", %{
          actor_id: opts[:actor_id],
          actor_username: opts[:actor_username],
          target_type: "user_profile",
          target_id: user_id,
          tenant_id: tenant_id,
          portal: "ca"
        })
        :ok

      {:error, _} = err -> err
    end
  end

  @impl true
  def list_audit_events(filters, opts \\ []) do
    tenant_id = opts[:tenant_id]
    full_filters = [{:tenant_id, tenant_id} | filters]
    {:ok, PkiPlatformEngine.PlatformAudit.list_events(full_filters)}
  end

  defp get_tenant_name(nil), do: ""
  defp get_tenant_name(tenant_id) do
    case PkiPlatformEngine.PlatformRepo.get(PkiPlatformEngine.Tenant, tenant_id) do
      nil -> ""
      tenant -> tenant.name
    end
  end
```

- [ ] **Step 3: Implement in Mock**

In `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/mock.ex`, add before the `reset_password` implementation:

```elixir
  @impl true
  def list_portal_users(_opts \\ []) do
    {:ok, get_state(:users) |> Enum.map(fn u ->
      Map.merge(u, %{role_id: "role-#{u.id}", email: "#{u.username}@example.com"})
    end)}
  end

  @impl true
  def create_portal_user(attrs, _opts \\ []) do
    user = %{
      id: Uniq.UUID.uuid7(),
      username: attrs[:username] || attrs["username"],
      display_name: attrs[:display_name] || attrs["display_name"],
      email: attrs[:email] || attrs["email"],
      role: attrs[:role] || attrs["role"],
      status: "active",
      role_id: Uniq.UUID.uuid7()
    }
    update_state(:users, fn users -> users ++ [user] end)
    {:ok, user}
  end

  @impl true
  def suspend_user_role(role_id, _opts \\ []) do
    update_state(:users, fn users ->
      Enum.map(users, fn u ->
        if Map.get(u, :role_id) == role_id, do: Map.put(u, :status, "suspended"), else: u
      end)
    end)
    {:ok, %{id: role_id, status: "suspended"}}
  end

  @impl true
  def activate_user_role(role_id, _opts \\ []) do
    update_state(:users, fn users ->
      Enum.map(users, fn u ->
        if Map.get(u, :role_id) == role_id, do: Map.put(u, :status, "active"), else: u
      end)
    end)
    {:ok, %{id: role_id, status: "active"}}
  end

  @impl true
  def delete_user_role(role_id, _opts \\ []) do
    update_state(:users, fn users ->
      Enum.reject(users, fn u -> Map.get(u, :role_id) == role_id end)
    end)
    {:ok, %{id: role_id}}
  end

  @impl true
  def reset_user_password(_user_id, _opts \\ []), do: :ok

  @impl true
  def list_audit_events(_filters, _opts \\ []) do
    {:ok, [
      %{id: "evt-1", timestamp: DateTime.utc_now(), action: "user_created", actor_username: "admin1", target_type: "user_profile", details: %{}},
      %{id: "evt-2", timestamp: DateTime.utc_now(), action: "login", actor_username: "admin1", target_type: nil, details: %{}}
    ]}
  end
```

Also add these callbacks to any other implementations (stateful_mock.ex, http.ex) with stub implementations.

- [ ] **Step 4: Verify compilation**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_portal && mix compile
```

- [ ] **Step 5: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki && git add src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client.ex src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/direct.ex src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/mock.ex && git commit -m "feat(ca-portal): add platform-level user CRUD and audit to CA engine client

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

(Remember to also add stateful_mock.ex and http.ex if modified.)

---

## Task 5: CA Portal — UsersLive Rewrite

**Files:**
- Modify: `src/pki_ca_portal/lib/pki_ca_portal_web/live/users_live.ex`

- [ ] **Step 1: Rewrite UsersLive to use platform-level user management**

Replace the entire content of `src/pki_ca_portal/lib/pki_ca_portal_web/live/users_live.ex` with:

```elixir
defmodule PkiCaPortalWeb.UsersLive do
  use PkiCaPortalWeb, :live_view

  alias PkiCaPortal.CaEngineClient

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_data)

    {:ok,
     assign(socket,
       page_title: "User Management",
       users: [],
       filtered_users: [],
       role_filter: "all",
       loading: true,
       page: 1,
       per_page: 10
     )}
  end

  @impl true
  def handle_info(:load_data, socket) do
    opts = actor_opts(socket)
    users = case CaEngineClient.list_portal_users(opts) do
      {:ok, u} -> u
      {:error, _} -> []
    end

    {:noreply,
     assign(socket,
       users: users,
       filtered_users: users,
       loading: false
     )}
  end

  @impl true
  def handle_event("create_user", params, socket) do
    attrs = %{
      username: params["username"],
      display_name: params["display_name"],
      email: params["email"],
      role: params["role"]
    }

    opts = actor_opts(socket)

    case CaEngineClient.create_portal_user(attrs, opts) do
      {:ok, _user} ->
        send(self(), :load_data)
        {:noreply, put_flash(socket, :info, "User created. Invitation email sent.")}

      {:error, {:validation_error, errors}} ->
        msg = format_validation_errors(errors)
        {:noreply, put_flash(socket, :error, "Failed to create user: #{msg}")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to create user: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("suspend_user", %{"role-id" => role_id}, socket) do
    case CaEngineClient.suspend_user_role(role_id, actor_opts(socket)) do
      {:ok, _} ->
        send(self(), :load_data)
        {:noreply, put_flash(socket, :info, "User suspended.")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to suspend user: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("activate_user", %{"role-id" => role_id}, socket) do
    case CaEngineClient.activate_user_role(role_id, actor_opts(socket)) do
      {:ok, _} ->
        send(self(), :load_data)
        {:noreply, put_flash(socket, :info, "User activated.")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to activate user: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("reset_password", %{"user-id" => user_id}, socket) do
    case CaEngineClient.reset_user_password(user_id, actor_opts(socket)) do
      :ok ->
        {:noreply, put_flash(socket, :info, "Password reset. New credentials emailed.")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to reset password: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("delete_user", %{"role-id" => role_id}, socket) do
    case CaEngineClient.delete_user_role(role_id, actor_opts(socket)) do
      {:ok, _} ->
        send(self(), :load_data)
        {:noreply, put_flash(socket, :info, "User removed.")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to remove user: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("filter_role", %{"role" => role}, socket) do
    filtered = filter_users(socket.assigns.users, role)
    {:noreply, assign(socket, role_filter: role, filtered_users: filtered, page: 1)}
  end

  @impl true
  def handle_event("change_page", %{"page" => page}, socket) do
    {:noreply, assign(socket, page: String.to_integer(page))}
  end

  defp filter_users(users, "all"), do: users
  defp filter_users(users, role), do: Enum.filter(users, &(&1.role == role))

  defp actor_opts(socket) do
    user = socket.assigns.current_user
    base = [
      actor_id: user[:id] || user["id"],
      actor_username: user[:username] || user["username"]
    ]

    case socket.assigns[:tenant_id] do
      nil -> base
      tid -> [{:tenant_id, tid} | base]
    end
  end

  defp format_validation_errors(errors) when is_map(errors) do
    Enum.map_join(errors, ", ", fn {field, msgs} -> "#{field}: #{Enum.join(List.wrap(msgs), ", ")}" end)
  end
  defp format_validation_errors(errors), do: inspect(errors)

  defp role_badge_class(role) do
    case role do
      "ca_admin" -> "badge-primary"
      "key_manager" -> "badge-info"
      "auditor" -> "badge-warning"
      _ -> "badge-ghost"
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div id="users-page" class="space-y-6">
      <%!-- Create user form --%>
      <div id="create-user-form" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <h2 class="text-sm font-semibold text-base-content mb-4">Create User & Send Invite</h2>
          <form phx-submit="create_user" class="grid grid-cols-1 md:grid-cols-5 gap-4 items-end">
            <div>
              <label for="username" class="block text-xs font-medium text-base-content/60 mb-1">Username</label>
              <input type="text" name="username" id="user-username" required class="input input-bordered input-sm w-full" />
            </div>
            <div>
              <label for="display_name" class="block text-xs font-medium text-base-content/60 mb-1">Display Name</label>
              <input type="text" name="display_name" id="user-display-name" required class="input input-bordered input-sm w-full" />
            </div>
            <div>
              <label for="email" class="block text-xs font-medium text-base-content/60 mb-1">Email</label>
              <input type="email" name="email" id="user-email" required class="input input-bordered input-sm w-full" />
            </div>
            <div>
              <label for="role" class="block text-xs font-medium text-base-content/60 mb-1">Role</label>
              <select name="role" id="user-role" class="select select-bordered select-sm w-full">
                <option value="ca_admin">CA Admin</option>
                <option value="key_manager">Key Manager</option>
                <option value="auditor">Auditor</option>
              </select>
            </div>
            <div>
              <button type="submit" class="btn btn-primary btn-sm w-full">
                <.icon name="hero-envelope" class="size-4" />
                Create & Send Invite
              </button>
            </div>
          </form>
        </div>
      </div>

      <%!-- Filter --%>
      <div id="user-filter" class="flex items-center justify-end">
        <form phx-change="filter_role" class="flex items-center gap-2">
          <label for="role" class="text-sm text-base-content/60">Filter by role:</label>
          <select name="role" id="role-filter" class="select select-sm select-bordered">
            <option value="all" selected={@role_filter == "all"}>All</option>
            <option value="ca_admin" selected={@role_filter == "ca_admin"}>CA Admin</option>
            <option value="key_manager" selected={@role_filter == "key_manager"}>Key Manager</option>
            <option value="auditor" selected={@role_filter == "auditor"}>Auditor</option>
          </select>
        </form>
      </div>

      <%!-- Users table --%>
      <% paginated_users = @filtered_users |> Enum.drop((@page - 1) * @per_page) |> Enum.take(@per_page) %>
      <% total_users = length(@filtered_users) %>
      <% total_pages = max(ceil(total_users / @per_page), 1) %>
      <% start_idx = min((@page - 1) * @per_page + 1, total_users) %>
      <% end_idx = min(@page * @per_page, total_users) %>
      <div id="user-table" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-0">
          <div class="overflow-x-auto">
            <table class="table table-sm">
              <thead>
                <tr class="text-xs uppercase text-base-content/50">
                  <th>Username</th>
                  <th>Name</th>
                  <th>Email</th>
                  <th>Role</th>
                  <th>Status</th>
                  <th class="text-right">Actions</th>
                </tr>
              </thead>
              <tbody id="user-list">
                <tr :for={user <- paginated_users} id={"user-#{user.id}"} class="hover">
                  <td class="font-mono text-xs">{user.username}</td>
                  <td>{user.display_name}</td>
                  <td class="text-xs">{user.email}</td>
                  <td>
                    <span class={"badge badge-sm #{role_badge_class(user.role)}"}>{user.role}</span>
                  </td>
                  <td>
                    <span class={["badge badge-sm", if(user.status == "active", do: "badge-success", else: "badge-warning")]}>
                      {user.status}
                    </span>
                  </td>
                  <td class="text-right space-x-1">
                    <%= if user.status == "active" do %>
                      <button phx-click="suspend_user" phx-value-role-id={user.role_id} class="btn btn-warning btn-sm btn-outline">
                        Suspend
                      </button>
                    <% else %>
                      <button phx-click="activate_user" phx-value-role-id={user.role_id} class="btn btn-success btn-sm btn-outline">
                        Activate
                      </button>
                    <% end %>
                    <button phx-click="reset_password" phx-value-user-id={user.id} class="btn btn-info btn-sm btn-outline">
                      Reset Pwd
                    </button>
                    <button phx-click="delete_user" phx-value-role-id={user.role_id}
                      data-confirm="Remove this user's access? They will no longer be able to log in to this portal."
                      class="btn btn-error btn-sm btn-outline">
                      <.icon name="hero-trash" class="size-3.5" />
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <div :if={total_users > 0} class="flex items-center justify-between px-5 py-3 border-t border-base-300 text-sm">
            <span class="text-base-content/60">
              Showing {start_idx}–{end_idx} of {total_users}
            </span>
            <div class="join">
              <button class="join-item btn btn-sm" phx-click="change_page" phx-value-page={@page - 1} disabled={@page == 1}>«</button>
              <button class="join-item btn btn-sm btn-active">{@page}</button>
              <button class="join-item btn btn-sm" phx-click="change_page" phx-value-page={@page + 1} disabled={@page >= total_pages}>»</button>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
  end
end
```

- [ ] **Step 2: Verify compilation**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_portal && mix compile
```

- [ ] **Step 3: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki && git add src/pki_ca_portal/lib/pki_ca_portal_web/live/users_live.ex && git commit -m "feat(ca-portal): rewrite UsersLive for platform-level user management with email invitations

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: CA Portal — Audit Log + Session Audit

**Files:**
- Modify: `src/pki_ca_portal/lib/pki_ca_portal_web/live/audit_log_live.ex`
- Modify: `src/pki_ca_portal/lib/pki_ca_portal_web/controllers/session_controller.ex`
- Modify: `src/pki_ca_portal/lib/pki_ca_portal_web/live/profile_live.ex`

- [ ] **Step 1: Add category filter to AuditLogLive**

In `src/pki_ca_portal/lib/pki_ca_portal_web/live/audit_log_live.ex`, update the mount to add a `category` assign:

Add `category: "all"` to the assigns in mount. Then update `handle_info(:load_data)` to also load platform audit events:

```elixir
  @impl true
  def handle_info(:load_data, socket) do
    opts = tenant_opts(socket)

    ca_events =
      case CaEngineClient.query_audit_log([], opts) do
        {:ok, events} -> Enum.map(events, &Map.put(&1, :category, "ca_operations"))
        {:error, _} -> []
      end

    platform_events =
      case CaEngineClient.list_audit_events([], opts) do
        {:ok, events} -> Enum.map(events, fn e ->
          %{
            event_id: e.id || e[:id],
            timestamp: e.timestamp || e[:timestamp],
            action: e.action || e[:action],
            actor: e.actor_username || e[:actor_username] || "system",
            category: "user_management"
          }
        end)
        {:error, _} -> []
      end

    all_events = (ca_events ++ platform_events)
      |> Enum.sort_by(& &1.timestamp, {:desc, DateTime})

    ca_instances =
      case CaEngineClient.list_ca_instances(opts) do
        {:ok, instances} -> instances
        {:error, _} -> []
      end

    {:noreply,
     assign(socket,
       events: all_events,
       ca_instances: ca_instances,
       loading: false
     )}
  end
```

Add a category filter dropdown in the render template (in the filter form, add before the Action dropdown):

```heex
            <div>
              <label for="category" class="block text-xs font-medium text-base-content/60 mb-1">Category</label>
              <select name="category" id="filter-category" class="select select-bordered select-sm">
                <option value="all">All</option>
                <option value="ca_operations">CA Operations</option>
                <option value="user_management">User Management</option>
              </select>
            </div>
```

And add the user management actions to the Action dropdown:

```heex
                <option value="user_created">User Created</option>
                <option value="user_suspended">User Suspended</option>
                <option value="user_activated">User Activated</option>
                <option value="password_reset">Password Reset</option>
                <option value="password_changed">Password Changed</option>
                <option value="profile_updated">Profile Updated</option>
```

Update the filter event handler to support category filtering.

- [ ] **Step 2: Add login audit to SessionController**

In `src/pki_ca_portal/lib/pki_ca_portal_web/controllers/session_controller.ex`, add after successful auth (after `put_session` calls, before `redirect`):

```elixir
        PkiPlatformEngine.PlatformAudit.log("login", %{
          actor_id: user[:id],
          actor_username: user[:username],
          tenant_id: tenant_id,
          portal: "ca",
          details: %{ca_instance_id: ca_instance_id}
        })
```

And after failed auth (in the `{:error, :invalid_credentials}` branch):

```elixir
        PkiPlatformEngine.PlatformAudit.log("login_failed", %{
          portal: "ca",
          details: %{username: username}
        })
```

- [ ] **Step 3: Add audit logging to ProfileLive**

In `src/pki_ca_portal/lib/pki_ca_portal_web/live/profile_live.ex`, after successful password change (`{:ok, _}` in `change_password` handler):

```elixir
        PkiPlatformEngine.PlatformAudit.log("password_changed", %{
          actor_id: user_id,
          actor_username: user[:username] || user["username"],
          tenant_id: socket.assigns[:tenant_id],
          portal: "ca"
        })
```

After successful profile update (before `push_navigate`):

```elixir
        PkiPlatformEngine.PlatformAudit.log("profile_updated", %{
          actor_id: user_id,
          actor_username: user[:username] || user["username"],
          target_type: "user_profile",
          target_id: user_id,
          tenant_id: socket.assigns[:tenant_id],
          portal: "ca",
          details: %{display_name: display_name, email: email}
        })
```

- [ ] **Step 4: Verify compilation**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_portal && mix compile
```

- [ ] **Step 5: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki && git add src/pki_ca_portal/lib/pki_ca_portal_web/live/audit_log_live.ex src/pki_ca_portal/lib/pki_ca_portal_web/controllers/session_controller.ex src/pki_ca_portal/lib/pki_ca_portal_web/live/profile_live.ex && git commit -m "feat(ca-portal): add audit logging to login, profile, and combined audit log view

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: RA Portal — Engine Client Updates

**Files:**
- Modify: `src/pki_ra_portal/lib/pki_ra_portal/ra_engine_client.ex`
- Modify: `src/pki_ra_portal/lib/pki_ra_portal/ra_engine_client/direct.ex`
- Modify: `src/pki_ra_portal/lib/pki_ra_portal/ra_engine_client/mock.ex`

Same pattern as Task 4 but for RA portal. All functions identical except `portal: "ra"` instead of `"ca"`, and uses `Application.get_env(:pki_ra_portal, :portal_url, "")`.

- [ ] **Step 1: Add callbacks to RaEngineClient behaviour**

Add the same 7 callbacks as Task 4 Step 1 to `ra_engine_client.ex`:

```elixir
  @callback list_portal_users(keyword()) :: {:ok, [map()]} | {:error, term()}
  @callback create_portal_user(map(), keyword()) :: {:ok, map()} | {:error, term()}
  @callback suspend_user_role(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  @callback activate_user_role(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  @callback delete_user_role(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  @callback reset_user_password(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  @callback list_audit_events(keyword(), keyword()) :: {:ok, [map()]} | {:error, term()}
```

And delegators:

```elixir
  def list_portal_users(opts \\ []), do: impl().list_portal_users(opts)
  def create_portal_user(attrs, opts \\ []), do: impl().create_portal_user(attrs, opts)
  def suspend_user_role(role_id, opts \\ []), do: impl().suspend_user_role(role_id, opts)
  def activate_user_role(role_id, opts \\ []), do: impl().activate_user_role(role_id, opts)
  def delete_user_role(role_id, opts \\ []), do: impl().delete_user_role(role_id, opts)
  def reset_user_password(user_id, opts \\ []), do: impl().reset_user_password(user_id, opts)
  def list_audit_events(filters, opts \\ []), do: impl().list_audit_events(filters, opts)
```

- [ ] **Step 2: Implement in Direct client**

Same as Task 4 Step 2 but replace all `"ca"` with `"ra"` and `Application.get_env(:pki_ca_portal, :portal_url, "")` with `Application.get_env(:pki_ra_portal, :portal_url, "")`.

- [ ] **Step 3: Implement in Mock**

Same as Task 4 Step 3 but with RA-specific mock data (ra_admin, ra_officer roles).

- [ ] **Step 4: Verify compilation**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ra_portal && mix compile
```

- [ ] **Step 5: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki && git add src/pki_ra_portal/lib/pki_ra_portal/ra_engine_client.ex src/pki_ra_portal/lib/pki_ra_portal/ra_engine_client/direct.ex src/pki_ra_portal/lib/pki_ra_portal/ra_engine_client/mock.ex && git commit -m "feat(ra-portal): add platform-level user CRUD and audit to RA engine client

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

(Remember to also add http.ex if modified.)

---

## Task 8: RA Portal — UsersLive Rewrite

**Files:**
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/live/users_live.ex`

- [ ] **Step 1: Rewrite UsersLive**

Same structure as Task 5 but for RA portal:
- Module: `PkiRaPortalWeb.UsersLive`
- Uses `PkiRaPortal.RaEngineClient`
- Role options: `ra_admin`, `ra_officer`, `auditor`
- Remove RA instance filter (users are now at platform level, not instance-scoped)

The template and event handlers follow the exact same pattern as the CA version in Task 5, with these differences:
- `alias PkiRaPortal.RaEngineClient` instead of `PkiCaPortal.CaEngineClient`
- Role select options: `ra_admin`, `ra_officer`, `auditor`
- `role_badge_class`: `"ra_admin" -> "badge-primary"`, `"ra_officer" -> "badge-info"`, `"auditor" -> "badge-warning"`

- [ ] **Step 2: Verify compilation**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ra_portal && mix compile
```

- [ ] **Step 3: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki && git add src/pki_ra_portal/lib/pki_ra_portal_web/live/users_live.ex && git commit -m "feat(ra-portal): rewrite UsersLive for platform-level user management with email invitations

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: RA Portal — Audit Log Page + Session Audit

**Files:**
- Create: `src/pki_ra_portal/lib/pki_ra_portal_web/live/audit_log_live.ex`
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/router.ex`
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/components/layouts.ex`
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/controllers/session_controller.ex`
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/live/profile_live.ex`

- [ ] **Step 1: Create AuditLogLive for RA portal**

Create `src/pki_ra_portal/lib/pki_ra_portal_web/live/audit_log_live.ex`. This shows only platform audit events (RA doesn't have its own `PkiAuditTrail` like CA does):

```elixir
defmodule PkiRaPortalWeb.AuditLogLive do
  use PkiRaPortalWeb, :live_view

  alias PkiRaPortal.RaEngineClient

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_data)

    {:ok,
     assign(socket,
       page_title: "Audit Log",
       events: [],
       loading: true,
       filter_action: "",
       filter_actor: "",
       filter_date_from: "",
       filter_date_to: "",
       page: 1,
       per_page: 10
     )}
  end

  @impl true
  def handle_info(:load_data, socket) do
    opts = tenant_opts(socket)

    events =
      case RaEngineClient.list_audit_events([], opts) do
        {:ok, events} -> events
        {:error, _} -> []
      end

    {:noreply, assign(socket, events: events, loading: false)}
  end

  @impl true
  def handle_event("filter", params, socket) do
    filters =
      []
      |> maybe_add(:action, params["action"])
      |> maybe_add(:actor_username, params["actor"])
      |> maybe_add(:date_from, params["date_from"])
      |> maybe_add(:date_to, params["date_to"])

    events =
      case RaEngineClient.list_audit_events(filters, tenant_opts(socket)) do
        {:ok, events} -> events
        {:error, _} -> []
      end

    {:noreply,
     assign(socket,
       events: events,
       filter_action: params["action"] || "",
       filter_actor: params["actor"] || "",
       filter_date_from: params["date_from"] || "",
       filter_date_to: params["date_to"] || "",
       page: 1
     )}
  end

  @impl true
  def handle_event("change_page", %{"page" => page}, socket) do
    {:noreply, assign(socket, page: String.to_integer(page))}
  end

  defp tenant_opts(socket) do
    case socket.assigns[:tenant_id] do
      nil -> []
      tid -> [tenant_id: tid]
    end
  end

  defp maybe_add(filters, _key, nil), do: filters
  defp maybe_add(filters, _key, ""), do: filters
  defp maybe_add(filters, key, value), do: [{key, value} | filters]

  @impl true
  def render(assigns) do
    ~H"""
    <div id="audit-log-page" class="space-y-6">
      <%!-- Filter form --%>
      <div id="audit-filter" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-4">
          <form phx-submit="filter" class="flex flex-wrap items-end gap-3">
            <div>
              <label for="action" class="block text-xs font-medium text-base-content/60 mb-1">Action</label>
              <select name="action" id="filter-action" class="select select-bordered select-sm">
                <option value="">All</option>
                <option value="login" selected={@filter_action == "login"}>Login</option>
                <option value="login_failed" selected={@filter_action == "login_failed"}>Login Failed</option>
                <option value="user_created" selected={@filter_action == "user_created"}>User Created</option>
                <option value="user_suspended" selected={@filter_action == "user_suspended"}>User Suspended</option>
                <option value="user_activated" selected={@filter_action == "user_activated"}>User Activated</option>
                <option value="user_deleted" selected={@filter_action == "user_deleted"}>User Deleted</option>
                <option value="password_reset" selected={@filter_action == "password_reset"}>Password Reset</option>
                <option value="password_changed" selected={@filter_action == "password_changed"}>Password Changed</option>
                <option value="profile_updated" selected={@filter_action == "profile_updated"}>Profile Updated</option>
              </select>
            </div>
            <div>
              <label for="actor" class="block text-xs font-medium text-base-content/60 mb-1">Actor</label>
              <input type="text" name="actor" id="filter-actor" value={@filter_actor} class="input input-bordered input-sm w-40" placeholder="Search actor..." />
            </div>
            <div>
              <label for="date_from" class="block text-xs font-medium text-base-content/60 mb-1">From</label>
              <input type="date" name="date_from" id="filter-date-from" value={@filter_date_from} class="input input-bordered input-sm" />
            </div>
            <div>
              <label for="date_to" class="block text-xs font-medium text-base-content/60 mb-1">To</label>
              <input type="date" name="date_to" id="filter-date-to" value={@filter_date_to} class="input input-bordered input-sm" />
            </div>
            <div>
              <button type="submit" class="btn btn-primary btn-sm">
                <.icon name="hero-funnel" class="size-4" />
                Apply Filter
              </button>
            </div>
          </form>
        </div>
      </div>

      <%!-- Events table --%>
      <% paginated = @events |> Enum.drop((@page - 1) * @per_page) |> Enum.take(@per_page) %>
      <% total = length(@events) %>
      <% total_pages = max(ceil(total / @per_page), 1) %>
      <% start_idx = min((@page - 1) * @per_page + 1, total) %>
      <% end_idx = min(@page * @per_page, total) %>
      <div id="audit-table" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-0">
          <div class="overflow-x-auto">
            <table class="table table-sm">
              <thead>
                <tr class="text-xs uppercase text-base-content/50">
                  <th>Timestamp</th>
                  <th>Action</th>
                  <th>Actor</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody id="event-list">
                <tr :for={event <- paginated} id={"event-#{event.id}"} class="hover">
                  <td class="font-mono text-xs">{Calendar.strftime(event.timestamp, "%Y-%m-%d %H:%M:%S")}</td>
                  <td><span class="badge badge-sm badge-ghost">{event.action}</span></td>
                  <td>{event.actor_username || "system"}</td>
                  <td class="text-xs text-base-content/60">{inspect(event.details || %{})}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div :if={total > 0} class="flex items-center justify-between px-5 py-3 border-t border-base-300 text-sm">
            <span class="text-base-content/60">Showing {start_idx}–{end_idx} of {total}</span>
            <div class="join">
              <button class="join-item btn btn-sm" phx-click="change_page" phx-value-page={@page - 1} disabled={@page == 1}>«</button>
              <button class="join-item btn btn-sm btn-active">{@page}</button>
              <button class="join-item btn btn-sm" phx-click="change_page" phx-value-page={@page + 1} disabled={@page >= total_pages}>»</button>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
  end
end
```

- [ ] **Step 2: Add route and sidebar link**

In `src/pki_ra_portal/lib/pki_ra_portal_web/router.ex`, add inside `:authenticated` live_session:

```elixir
      live "/audit-log", AuditLogLive
```

In `src/pki_ra_portal/lib/pki_ra_portal_web/components/layouts.ex`, add a sidebar link after API Keys (before the Profile divider):

```heex
          <.sidebar_link href="/audit-log" icon="hero-document-text" label="Audit Log" current={@page_title} />
```

Add `is_active?` clause:

```elixir
  defp is_active?("Audit Log", "Audit Log"), do: true
```

- [ ] **Step 3: Add login audit to RA SessionController**

In `src/pki_ra_portal/lib/pki_ra_portal_web/controllers/session_controller.ex`, add audit logging for login success and failure (same pattern as Task 6 Step 2 but with `portal: "ra"`).

- [ ] **Step 4: Add audit logging to RA ProfileLive**

Same as Task 6 Step 3 but with `portal: "ra"` and `PkiRaPortal.RaEngineClient`.

- [ ] **Step 5: Verify compilation**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ra_portal && mix compile
```

- [ ] **Step 6: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki && git add src/pki_ra_portal/lib/pki_ra_portal_web/live/audit_log_live.ex src/pki_ra_portal/lib/pki_ra_portal_web/router.ex src/pki_ra_portal/lib/pki_ra_portal_web/components/layouts.ex src/pki_ra_portal/lib/pki_ra_portal_web/controllers/session_controller.ex src/pki_ra_portal/lib/pki_ra_portal_web/live/profile_live.ex && git commit -m "feat(ra-portal): add audit log page, login/profile audit logging

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

## Task 10: Smoke Test

- [ ] **Step 1: Run migration**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_platform_engine && mix ecto.migrate
```

- [ ] **Step 2: Compile all portals**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_platform_portal && mix compile
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_portal && mix compile
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ra_portal && mix compile
```

Expected: All compile with exit 0 (pre-existing warnings only).

- [ ] **Step 3: Verify routes**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ra_portal && mix phx.routes | grep audit
```

Expected: Shows `/audit-log` route.
