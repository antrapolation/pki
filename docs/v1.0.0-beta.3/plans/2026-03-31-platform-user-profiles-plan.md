# Platform-Level User Profiles — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Centralize authentication in the platform database so login works without knowing the tenant upfront.

**Architecture:** A `user_profiles` table stores credentials (username + password_hash). A `user_tenant_roles` join table maps each user to tenant(s) with role and portal. Login authenticates against platform DB, resolves tenant, stores tenant_id in session. Engine-specific user records (ca_users, ra_users) stay in tenant DBs for engine operations.

**Tech Stack:** Elixir, Ecto, Argon2, Phoenix LiveView, PlatformRepo

---

## Task 1: Create Migration for user_profiles and user_tenant_roles

**Files:**
- Create: `src/pki_platform_engine/priv/platform_repo/migrations/20260331000001_create_user_profiles.exs`

- [ ] **Step 1: Write the migration**

```elixir
defmodule PkiPlatformEngine.PlatformRepo.Migrations.CreateUserProfiles do
  use Ecto.Migration

  def change do
    create table(:user_profiles, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :username, :string, null: false
      add :password_hash, :string, null: false
      add :display_name, :string
      add :email, :string
      add :status, :string, null: false, default: "active"
      add :must_change_password, :boolean, default: false
      add :credential_expires_at, :utc_datetime
      timestamps()
    end

    create unique_index(:user_profiles, [:username])
    create index(:user_profiles, [:email])
    create index(:user_profiles, [:status])

    create table(:user_tenant_roles, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_profile_id, references(:user_profiles, type: :binary_id, on_delete: :delete_all), null: false
      add :tenant_id, references(:tenants, type: :binary_id, on_delete: :delete_all), null: false
      add :role, :string, null: false
      add :portal, :string, null: false
      add :ca_instance_id, :string
      add :status, :string, null: false, default: "active"
      timestamps()
    end

    create unique_index(:user_tenant_roles, [:user_profile_id, :tenant_id, :portal])
    create index(:user_tenant_roles, [:tenant_id])
    create index(:user_tenant_roles, [:user_profile_id])
  end
end
```

- [ ] **Step 2: Run the migration**

```bash
cd src/pki_platform_engine && POSTGRES_PORT=5434 mix ecto.migrate
```

- [ ] **Step 3: Commit**

```bash
git add priv/platform_repo/migrations/20260331000001_create_user_profiles.exs
git commit -m "feat: add user_profiles and user_tenant_roles tables"
```

---

## Task 2: Create UserProfile and UserTenantRole Schemas

**Files:**
- Create: `src/pki_platform_engine/lib/pki_platform_engine/user_profile.ex`
- Create: `src/pki_platform_engine/lib/pki_platform_engine/user_tenant_role.ex`

- [ ] **Step 1: Create UserProfile schema**

```elixir
defmodule PkiPlatformEngine.UserProfile do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  schema "user_profiles" do
    field :username, :string
    field :password, :string, virtual: true
    field :password_hash, :string
    field :display_name, :string
    field :email, :string
    field :status, :string, default: "active"
    field :must_change_password, :boolean, default: false
    field :credential_expires_at, :utc_datetime

    has_many :tenant_roles, PkiPlatformEngine.UserTenantRole
    timestamps()
  end

  @roles_ca ["ca_admin", "key_manager", "auditor"]
  @roles_ra ["ra_admin", "ra_officer", "auditor"]
  @all_roles @roles_ca ++ @roles_ra |> Enum.uniq()

  def valid_roles, do: @all_roles

  def changeset(profile, attrs) do
    profile
    |> cast(attrs, [:username, :display_name, :email, :status, :must_change_password, :credential_expires_at])
    |> validate_required([:username])
    |> validate_length(:username, min: 3, max: 50)
    |> validate_format(:email, ~r/^[^\s]+@[^\s]+\.[^\s]+$/, message: "must be a valid email")
    |> validate_inclusion(:status, ["active", "suspended"])
    |> unique_constraint(:username)
    |> maybe_generate_id()
  end

  def registration_changeset(profile, attrs) do
    profile
    |> cast(attrs, [:username, :password, :display_name, :email, :must_change_password, :credential_expires_at])
    |> validate_required([:username, :password])
    |> validate_length(:username, min: 3, max: 50)
    |> validate_length(:password, min: 8, max: 100)
    |> validate_format(:email, ~r/^[^\s]+@[^\s]+\.[^\s]+$/, message: "must be a valid email")
    |> unique_constraint(:username)
    |> hash_password()
    |> maybe_generate_id()
  end

  def password_changeset(profile, attrs) do
    profile
    |> cast(attrs, [:password, :must_change_password])
    |> validate_required([:password])
    |> validate_length(:password, min: 8, max: 100)
    |> hash_password()
    |> put_change(:credential_expires_at, nil)
  end

  defp hash_password(%{valid?: true, changes: %{password: password}} = changeset) do
    changeset
    |> put_change(:password_hash, Argon2.hash_pwd_salt(password))
    |> delete_change(:password)
  end

  defp hash_password(changeset), do: changeset

  defp maybe_generate_id(%{data: %{id: nil}} = changeset) do
    put_change(changeset, :id, Uniq.UUID.uuid7())
  end

  defp maybe_generate_id(changeset), do: changeset
end
```

- [ ] **Step 2: Create UserTenantRole schema**

```elixir
defmodule PkiPlatformEngine.UserTenantRole do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  schema "user_tenant_roles" do
    belongs_to :user_profile, PkiPlatformEngine.UserProfile
    belongs_to :tenant, PkiPlatformEngine.Tenant
    field :role, :string
    field :portal, :string
    field :ca_instance_id, :string
    field :status, :string, default: "active"
    timestamps()
  end

  @valid_roles ["ca_admin", "key_manager", "ra_admin", "ra_officer", "auditor"]
  @valid_portals ["ca", "ra"]

  def changeset(role, attrs) do
    role
    |> cast(attrs, [:user_profile_id, :tenant_id, :role, :portal, :ca_instance_id, :status])
    |> validate_required([:user_profile_id, :tenant_id, :role, :portal])
    |> validate_inclusion(:role, @valid_roles)
    |> validate_inclusion(:portal, @valid_portals)
    |> validate_inclusion(:status, ["active", "suspended"])
    |> foreign_key_constraint(:user_profile_id)
    |> foreign_key_constraint(:tenant_id)
    |> unique_constraint([:user_profile_id, :tenant_id, :portal])
    |> maybe_generate_id()
  end

  defp maybe_generate_id(%{data: %{id: nil}} = changeset) do
    put_change(changeset, :id, Uniq.UUID.uuid7())
  end

  defp maybe_generate_id(changeset), do: changeset
end
```

- [ ] **Step 3: Verify compilation**

```bash
cd src/pki_platform_engine && mix compile
```

- [ ] **Step 4: Commit**

```bash
git add lib/pki_platform_engine/user_profile.ex lib/pki_platform_engine/user_tenant_role.ex
git commit -m "feat: add UserProfile and UserTenantRole schemas"
```

---

## Task 3: Create PlatformAuth Module

**Files:**
- Create: `src/pki_platform_engine/lib/pki_platform_engine/platform_auth.ex`

This module handles authentication against the platform DB and tenant role resolution.

- [ ] **Step 1: Implement PlatformAuth**

```elixir
defmodule PkiPlatformEngine.PlatformAuth do
  @moduledoc """
  Authenticates users against the platform database and resolves tenant roles.
  """

  import Ecto.Query

  alias PkiPlatformEngine.{PlatformRepo, UserProfile, UserTenantRole}

  @doc """
  Authenticate a user by username and password.
  Returns {:ok, user_profile} or {:error, :invalid_credentials}.
  """
  def authenticate(username, password) do
    case PlatformRepo.one(from u in UserProfile, where: u.username == ^username and u.status == "active") do
      nil ->
        Argon2.no_user_verify()
        {:error, :invalid_credentials}

      user ->
        if Argon2.verify_pass(password, user.password_hash) do
          {:ok, user}
        else
          {:error, :invalid_credentials}
        end
    end
  end

  @doc """
  Get active tenant roles for a user, optionally filtered by portal ("ca" or "ra").
  Returns a list of UserTenantRole structs with tenant preloaded.
  """
  def get_tenant_roles(user_profile_id, opts \\ []) do
    query = from r in UserTenantRole,
      where: r.user_profile_id == ^user_profile_id and r.status == "active",
      preload: [:tenant]

    query =
      case Keyword.get(opts, :portal) do
        nil -> query
        portal -> from r in query, where: r.portal == ^portal
      end

    PlatformRepo.all(query)
  end

  @doc """
  Authenticate and resolve tenant in one call.
  Returns {:ok, user_profile, tenant_role} or {:error, reason}.
  """
  def authenticate_for_portal(username, password, portal) do
    with {:ok, user} <- authenticate(username, password) do
      case get_tenant_roles(user.id, portal: portal) do
        [] ->
          {:error, :no_tenant_assigned}

        [role | _] ->
          {:ok, user, role}
      end
    end
  end

  @doc """
  Create a user profile with password.
  Returns {:ok, user_profile} or {:error, changeset}.
  """
  def create_user_profile(attrs) do
    %UserProfile{}
    |> UserProfile.registration_changeset(attrs)
    |> PlatformRepo.insert()
  end

  @doc """
  Find or create a user profile by username.
  If exists, returns the existing profile without changing the password.
  """
  def find_or_create_user_profile(attrs) do
    username = attrs[:username] || attrs["username"]

    case PlatformRepo.get_by(UserProfile, username: username) do
      nil -> create_user_profile(attrs)
      existing -> {:ok, existing}
    end
  end

  @doc """
  Assign a tenant role to a user profile.
  Returns {:ok, role} or {:error, changeset}.
  """
  def assign_tenant_role(user_profile_id, tenant_id, attrs) do
    full_attrs =
      attrs
      |> Map.put(:user_profile_id, user_profile_id)
      |> Map.put(:tenant_id, tenant_id)

    %UserTenantRole{}
    |> UserTenantRole.changeset(full_attrs)
    |> PlatformRepo.insert(on_conflict: :nothing)
  end

  @doc """
  Reset a user profile's password.
  Returns {:ok, user_profile} or {:error, changeset}.
  """
  def reset_password(user_profile_id, new_password, opts \\ []) do
    case PlatformRepo.get(UserProfile, user_profile_id) do
      nil ->
        {:error, :not_found}

      user ->
        user
        |> UserProfile.password_changeset(%{
          password: new_password,
          must_change_password: Keyword.get(opts, :must_change_password, true)
        })
        |> PlatformRepo.update()
    end
  end

  @doc """
  Reactivate a suspended user profile.
  """
  def reactivate(user_profile_id) do
    case PlatformRepo.get(UserProfile, user_profile_id) do
      nil -> {:error, :not_found}
      user -> user |> UserProfile.changeset(%{status: "active"}) |> PlatformRepo.update()
    end
  end

  @doc """
  Find a user profile by username.
  """
  def get_by_username(username) do
    case PlatformRepo.get_by(UserProfile, username: username) do
      nil -> {:error, :not_found}
      user -> {:ok, user}
    end
  end
end
```

- [ ] **Step 2: Verify compilation**

```bash
cd src/pki_platform_engine && mix compile
```

- [ ] **Step 3: Commit**

```bash
git add lib/pki_platform_engine/platform_auth.ex
git commit -m "feat: add PlatformAuth — authenticate against platform DB, resolve tenant roles"
```

---

## Task 4: Update Tenant Activation to Create Platform User Profiles

**Files:**
- Modify: `src/pki_platform_portal/lib/pki_platform_portal_web/live/tenant_detail_live.ex`

The `ensure_admins` handler must now:
1. Create user_profile in platform DB (or find existing)
2. Assign tenant roles in platform DB
3. Create ca_user/ra_user in tenant DB (for engine-specific data)
4. Send email

- [ ] **Step 1: Update ensure_admins to create platform user profiles**

In `tenant_detail_live.ex`, update the `create_ca_admin` and `create_ra_admin` private functions to also create platform-level records.

Replace the existing `create_ca_admin/4` function:

```elixir
defp create_ca_admin(tenant, ca_instance_id, username, password) do
  alias PkiPlatformEngine.PlatformAuth

  # 1. Create or find user profile in platform DB
  with {:ok, profile} <- PlatformAuth.find_or_create_user_profile(%{
         username: username,
         password: password,
         display_name: "#{tenant.name} CA Admin",
         email: tenant.email,
         must_change_password: true
       }),
       # 2. Assign CA admin role for this tenant
       {:ok, _role} <- PlatformAuth.assign_tenant_role(profile.id, tenant.id, %{
         role: "ca_admin",
         portal: "ca",
         ca_instance_id: ca_instance_id
       }),
       # 3. Create ca_user in tenant DB for engine operations
       result <- PkiCaEngine.UserManagement.register_user(tenant.id, ca_instance_id, %{
         username: username,
         password: password,
         role: "ca_admin",
         display_name: "#{tenant.name} CA Admin",
         must_change_password: true,
         credential_expires_at: DateTime.utc_now() |> DateTime.add(24, :hour) |> DateTime.truncate(:second)
       }) do
    case result do
      {:ok, _user} -> :ok
      {:error, reason} -> {:error, reason}
    end
  else
    {:error, reason} -> {:error, reason}
  end
rescue
  e -> {:error, Exception.message(e)}
end
```

Replace the existing `create_ra_admin/3` function:

```elixir
defp create_ra_admin(tenant, username, password) do
  alias PkiPlatformEngine.PlatformAuth

  with {:ok, profile} <- PlatformAuth.find_or_create_user_profile(%{
         username: username,
         password: password,
         display_name: "#{tenant.name} RA Admin",
         email: tenant.email,
         must_change_password: true
       }),
       {:ok, _role} <- PlatformAuth.assign_tenant_role(profile.id, tenant.id, %{
         role: "ra_admin",
         portal: "ra"
       }),
       result <- PkiRaEngine.UserManagement.register_user(tenant.id, %{
         username: username,
         password: password,
         role: "ra_admin",
         display_name: "#{tenant.name} RA Admin",
         tenant_id: tenant.id,
         must_change_password: true,
         credential_expires_at: DateTime.utc_now() |> DateTime.add(24, :hour) |> DateTime.truncate(:second)
       }) do
    case result do
      {:ok, _user} -> :ok
      {:error, reason} -> {:error, reason}
    end
  else
    {:error, reason} -> {:error, reason}
  end
rescue
  e -> {:error, Exception.message(e)}
end
```

- [ ] **Step 2: Update recreate_ca_admin to reset platform password**

Replace the password reset section in `recreate_ca_admin`:

```elixir
user ->
  # Reset password in platform DB
  case PkiPlatformEngine.PlatformAuth.get_by_username(username) do
    {:ok, profile} ->
      PkiPlatformEngine.PlatformAuth.reset_password(profile.id, password)
      if profile.status == "suspended", do: PkiPlatformEngine.PlatformAuth.reactivate(profile.id)
    {:error, _} -> :ok
  end

  # Reactivate if suspended and reset password in tenant DB
  if user.status == "suspended" do
    PkiCaEngine.UserManagement.update_user(tenant.id, user.id, %{status: "active"})
  end

  case PkiCaEngine.UserManagement.update_user_password(tenant.id, user, %{
         password: password,
         must_change_password: true
       }) do
    {:ok, _} -> []
    {:error, reason} -> ["CA admin reset failed: #{inspect(reason)}"]
  end
```

Apply the same pattern for `recreate_ra_admin`.

- [ ] **Step 3: Verify compilation**

```bash
cd src/pki_platform_portal && mix compile
```

- [ ] **Step 4: Commit**

```bash
git add src/pki_platform_portal/lib/pki_platform_portal_web/live/tenant_detail_live.ex
git commit -m "feat: create platform user profiles during tenant activation"
```

---

## Task 5: Update CA Portal Login to Use PlatformAuth

**Files:**
- Modify: `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/direct.ex:29-52`
- Modify: `src/pki_ca_portal/lib/pki_ca_portal_web/controllers/session_controller.ex`

- [ ] **Step 1: Update CaEngineClient.Direct authenticate functions**

Replace the `authenticate/3` and `authenticate_with_session/3` functions in `direct.ex`:

```elixir
@impl true
def authenticate(username, password, opts \\ []) do
  case PkiPlatformEngine.PlatformAuth.authenticate_for_portal(username, password, "ca") do
    {:ok, user, role} ->
      {:ok, %{
        id: user.id,
        username: user.username,
        role: role.role,
        display_name: user.display_name,
        tenant_id: role.tenant_id,
        ca_instance_id: role.ca_instance_id,
        must_change_password: user.must_change_password,
        credential_expires_at: user.credential_expires_at
      }}

    {:error, :invalid_credentials} = err -> err
    {:error, :no_tenant_assigned} -> {:error, :invalid_credentials}
  end
end

@impl true
def authenticate_with_session(username, password, opts \\ []) do
  case PkiPlatformEngine.PlatformAuth.authenticate_for_portal(username, password, "ca") do
    {:ok, user, role} ->
      user_map = %{
        id: user.id,
        username: user.username,
        role: role.role,
        display_name: user.display_name,
        tenant_id: role.tenant_id,
        ca_instance_id: role.ca_instance_id,
        must_change_password: user.must_change_password,
        credential_expires_at: user.credential_expires_at
      }
      {:ok, user_map, %{}}

    {:error, :invalid_credentials} = err -> err
    {:error, :no_tenant_assigned} -> {:error, :invalid_credentials}
  end
end
```

- [ ] **Step 2: Remove the resolve_tenant_id hack from CA SessionController**

In `session_controller.ex`, remove the `resolve_tenant_id` function and the tenant resolution from username. The `tenant_id` now comes from the authenticate response:

```elixir
def create(conn, %{"session" => %{"username" => username, "password" => password} = params}) do
  ca_instance_id = parse_instance_id(params["ca_instance_id"])

  case CaEngineClient.authenticate_with_session(username, password) do
    {:ok, user, session_info} ->
      tenant_id = user[:tenant_id]
      # ... rest stays the same
```

Remove the `resolve_tenant_id/2` private function entirely.

- [ ] **Step 3: Verify compilation**

```bash
cd src/pki_ca_portal && mix compile
```

- [ ] **Step 4: Commit**

```bash
git add src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/direct.ex
git add src/pki_ca_portal/lib/pki_ca_portal_web/controllers/session_controller.ex
git commit -m "feat: CA portal login authenticates via PlatformAuth"
```

---

## Task 6: Update RA Portal Login to Use PlatformAuth

**Files:**
- Modify: `src/pki_ra_portal/lib/pki_ra_portal/ra_engine_client/direct.ex:17-30`
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/controllers/session_controller.ex`

- [ ] **Step 1: Update RaEngineClient.Direct authenticate functions**

Replace the `authenticate/2` and `authenticate_with_session/2` functions in `direct.ex`:

```elixir
@impl true
def authenticate(username, password) do
  case PkiPlatformEngine.PlatformAuth.authenticate_for_portal(username, password, "ra") do
    {:ok, user, role} ->
      {:ok, %{
        id: user.id,
        username: user.username,
        role: role.role,
        display_name: user.display_name,
        tenant_id: role.tenant_id,
        must_change_password: user.must_change_password,
        credential_expires_at: user.credential_expires_at
      }}

    {:error, :invalid_credentials} = err -> err
    {:error, :no_tenant_assigned} -> {:error, :invalid_credentials}
  end
end

@impl true
def authenticate_with_session(username, password) do
  case PkiPlatformEngine.PlatformAuth.authenticate_for_portal(username, password, "ra") do
    {:ok, user, role} ->
      user_map = %{
        id: user.id,
        username: user.username,
        role: role.role,
        display_name: user.display_name,
        tenant_id: role.tenant_id,
        must_change_password: user.must_change_password,
        credential_expires_at: user.credential_expires_at
      }
      {:ok, user_map, %{}}

    {:error, :invalid_credentials} = err -> err
    {:error, :no_tenant_assigned} -> {:error, :invalid_credentials}
  end
end
```

- [ ] **Step 2: Verify compilation**

```bash
cd src/pki_ra_portal && mix compile
```

- [ ] **Step 3: Commit**

```bash
git add src/pki_ra_portal/lib/pki_ra_portal/ra_engine_client/direct.ex
git commit -m "feat: RA portal login authenticates via PlatformAuth"
```

---

## Task 7: Update CaEngineClient.Direct — needs_setup and reset_password

**Files:**
- Modify: `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/direct.ex`

`needs_setup?` and `reset_password` should also check platform DB:

- [ ] **Step 1: Update needs_setup? to check platform DB**

```elixir
@impl true
def needs_setup?(ca_instance_id, opts \\ []) do
  tenant_id = opts[:tenant_id]

  if tenant_id do
    import Ecto.Query
    count = PkiPlatformEngine.PlatformRepo.one(
      from r in PkiPlatformEngine.UserTenantRole,
        where: r.tenant_id == ^tenant_id and r.portal == "ca" and r.status == "active",
        select: count(r.id)
    )
    count == 0
  else
    true
  end
end
```

- [ ] **Step 2: Update reset_password to reset in platform DB**

```elixir
@impl true
def reset_password(user_id, new_password, opts \\ []) do
  case PkiPlatformEngine.PlatformAuth.reset_password(user_id, new_password, must_change_password: false) do
    {:ok, _} -> :ok
    {:error, :not_found} ->
      # Fallback: try tenant DB for legacy users
      tenant_id = opts[:tenant_id]
      with {:ok, user} <- UserManagement.get_user(tenant_id, user_id),
           {:ok, _} <- UserManagement.update_user_password(tenant_id, user, %{password: new_password}) do
        :ok
      end
    {:error, _} = err -> err
  end
end
```

- [ ] **Step 3: Verify and commit**

```bash
cd src/pki_ca_portal && mix compile
git add src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/direct.ex
git commit -m "feat: needs_setup and reset_password check platform DB"
```

---

## Task 8: End-to-End Test

- [ ] **Step 1: Run migrations**

```bash
cd src/pki_platform_engine && POSTGRES_PORT=5434 mix ecto.migrate
```

- [ ] **Step 2: Restart all services**

```bash
source .env
# Start platform portal (includes CA/RA engines + validation)
cd src/pki_platform_portal && elixir --sname platform -S mix phx.server &
# Start CA portal
cd src/pki_ca_portal && PORT=4002 elixir --sname ca_portal -S mix phx.server &
# Start RA portal
cd src/pki_ra_portal && PORT=4004 elixir --sname ra_portal -S mix phx.server &
```

- [ ] **Step 3: Test activation flow**

1. Go to http://localhost:4006 (platform portal)
2. Create a new tenant (e.g., "test corp", slug: "test-corp")
3. Click Activate
4. Verify: user_profiles and user_tenant_roles created in platform DB
5. Verify: ca_users and ra_users created in tenant DB
6. Verify: credential email received

```bash
podman exec pki-postgres psql -U postgres -d pki_platform_dev -c "SELECT username, status FROM user_profiles"
podman exec pki-postgres psql -U postgres -d pki_platform_dev -c "SELECT up.username, utr.role, utr.portal, t.slug FROM user_tenant_roles utr JOIN user_profiles up ON up.id = utr.user_profile_id JOIN tenants t ON t.id = utr.tenant_id"
```

- [ ] **Step 4: Test login on CA portal**

1. Go to http://localhost:4002 (CA portal)
2. Login with credentials from email
3. Verify: login succeeds, session has correct tenant_id
4. Verify: dashboard shows correct tenant data

- [ ] **Step 5: Test login on RA portal**

Same flow on http://localhost:4004

- [ ] **Step 6: Test password reset**

1. Go to platform portal → tenant detail → Reset CA Admin
2. Check email for new CA credentials
3. Login to CA portal with new password
4. Verify: old password no longer works, new password works

- [ ] **Step 7: Commit any fixes**

```bash
git add -A && git commit -m "fix: end-to-end fixes for platform user profiles"
```

---

## Summary

| Task | What it delivers |
|------|-----------------|
| 1. Migration | user_profiles + user_tenant_roles tables in platform DB |
| 2. Schemas | UserProfile + UserTenantRole Ecto schemas |
| 3. PlatformAuth | authenticate, get_tenant_roles, create_user_profile, assign_tenant_role |
| 4. Activation | Creates platform profiles + tenant roles on tenant activation |
| 5. CA Login | CA portal authenticates via PlatformAuth |
| 6. RA Login | RA portal authenticates via PlatformAuth |
| 7. needs_setup + reset | Platform-aware setup check and password reset |
| 8. E2E Test | Verify full flow works |

**Total: 8 tasks.** After this, login works without knowing the tenant upfront. Schema supports multi-tenant users for the next release.
