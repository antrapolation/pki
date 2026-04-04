# RA Portal UX Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Redesign the RA Portal with a first-login setup wizard, role-adaptive dashboards, grouped sidebar navigation, and explicit CA connection management.

**Architecture:** New `ra_ca_connections` table in RA Engine with schema/migration, management module, and API endpoints. Portal gets 3 new LiveView pages (welcome, wizard, CA connection), a rewritten dashboard with role-based rendering, and a reorganized sidebar layout. All changes are additive — existing pages keep their functionality.

**Tech Stack:** Elixir, Phoenix LiveView, Ecto, DaisyUI/Tailwind CSS, Plug.Router (engine API)

---

## File Structure

### RA Engine (new + modified)
```
lib/pki_ra_engine/schema/ra_ca_connection.ex          (CREATE) — Ecto schema
lib/pki_ra_engine/ca_connection_management.ex          (CREATE) — CRUD module
lib/pki_ra_engine/api/ca_connection_controller.ex      (CREATE) — REST controller
lib/pki_ra_engine/api/authenticated_router.ex          (MODIFY) — add CA connection routes
priv/repo/migrations/20260405000001_create_ra_ca_connections.exs (CREATE)
test/pki_ra_engine/ca_connection_management_test.exs   (CREATE)
```

### RA Portal (new + modified)
```
lib/pki_ra_portal/ra_engine_client.ex                  (MODIFY) — add CA connection callbacks
lib/pki_ra_portal/ra_engine_client/direct.ex           (MODIFY) — implement CA connection functions
lib/pki_ra_portal_web/live/welcome_live.ex             (CREATE) — first-login welcome screen
lib/pki_ra_portal_web/live/setup_wizard_live.ex        (CREATE) — 5-step wizard
lib/pki_ra_portal_web/live/ca_connection_live.ex       (CREATE) — CA connection management page
lib/pki_ra_portal_web/live/dashboard_live.ex           (REWRITE) — role-adaptive dashboard
lib/pki_ra_portal_web/live/cert_profiles_live.ex       (MODIFY) — template picker + issuer key dropdown
lib/pki_ra_portal_web/components/layouts.ex            (MODIFY) — grouped sidebar with role visibility
lib/pki_ra_portal_web/router.ex                        (MODIFY) — add new routes
lib/pki_ra_portal_web/live/auth_hook.ex                (MODIFY) — first-login redirect to /welcome
```

---

## Phase 1: Engine — CA Connection Data Layer

### Task 1: Migration + Schema for `ra_ca_connections`

**Files:**
- Create: `src/pki_ra_engine/priv/repo/migrations/20260405000001_create_ra_ca_connections.exs`
- Create: `src/pki_ra_engine/lib/pki_ra_engine/schema/ra_ca_connection.ex`

- [ ] **Step 1: Write the migration**

```elixir
defmodule PkiRaEngine.Repo.Migrations.CreateRaCaConnections do
  use Ecto.Migration

  def change do
    create table(:ra_ca_connections, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :ra_instance_id, references(:ra_instances, type: :binary_id, on_delete: :delete_all), null: false
      add :issuer_key_id, :string, null: false
      add :issuer_key_name, :string
      add :algorithm, :string
      add :ca_instance_name, :string
      add :status, :string, default: "active", null: false
      add :connected_at, :utc_datetime, null: false
      add :connected_by, :binary_id

      timestamps()
    end

    create unique_index(:ra_ca_connections, [:ra_instance_id, :issuer_key_id])
    create index(:ra_ca_connections, [:status])
  end
end
```

- [ ] **Step 2: Write the Ecto schema**

```elixir
defmodule PkiRaEngine.Schema.RaCaConnection do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  @statuses ["active", "revoked"]

  schema "ra_ca_connections" do
    field :issuer_key_id, :string
    field :issuer_key_name, :string
    field :algorithm, :string
    field :ca_instance_name, :string
    field :status, :string, default: "active"
    field :connected_at, :utc_datetime
    field :connected_by, :binary_id

    belongs_to :ra_instance, PkiRaEngine.Schema.RaInstance

    timestamps()
  end

  @required_fields [:ra_instance_id, :issuer_key_id, :connected_at]
  @optional_fields [:issuer_key_name, :algorithm, :ca_instance_name, :status, :connected_by]

  def changeset(connection, attrs) do
    connection
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:status, @statuses)
    |> unique_constraint([:ra_instance_id, :issuer_key_id])
    |> foreign_key_constraint(:ra_instance_id)
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

- [ ] **Step 3: Run migration**

```bash
cd src/pki_ra_engine && mix ecto.migrate
```

- [ ] **Step 4: Compile and verify**

```bash
mix compile
```
Expected: No errors

- [ ] **Step 5: Commit**

```bash
git add src/pki_ra_engine/priv/repo/migrations/20260405000001_create_ra_ca_connections.exs \
        src/pki_ra_engine/lib/pki_ra_engine/schema/ra_ca_connection.ex
git commit -m "feat(ra-engine): add ra_ca_connections schema and migration"
```

---

### Task 2: CA Connection Management Module

**Files:**
- Create: `src/pki_ra_engine/lib/pki_ra_engine/ca_connection_management.ex`
- Create: `src/pki_ra_engine/test/pki_ra_engine/ca_connection_management_test.exs`

- [ ] **Step 1: Write the failing tests**

```elixir
defmodule PkiRaEngine.CaConnectionManagementTest do
  use PkiRaEngine.DataCase, async: true

  alias PkiRaEngine.CaConnectionManagement
  alias PkiRaEngine.RaInstanceManagement

  defp create_ra_instance! do
    {:ok, ra} = RaInstanceManagement.create_ra_instance(nil, %{name: "test-ra-#{System.unique_integer([:positive])}", created_by: "admin"})
    ra
  end

  describe "connect/3" do
    test "creates a connection between RA instance and issuer key" do
      ra = create_ra_instance!()
      attrs = %{
        issuer_key_id: "key-#{System.unique_integer([:positive])}",
        issuer_key_name: "Test Issuer Key",
        algorithm: "ECC-P256",
        ca_instance_name: "Test CA"
      }

      assert {:ok, conn} = CaConnectionManagement.connect(nil, ra.id, attrs)
      assert conn.ra_instance_id == ra.id
      assert conn.issuer_key_id == attrs.issuer_key_id
      assert conn.status == "active"
      assert conn.connected_at != nil
    end

    test "prevents duplicate connections" do
      ra = create_ra_instance!()
      key_id = "key-dup-#{System.unique_integer([:positive])}"
      attrs = %{issuer_key_id: key_id, issuer_key_name: "Key", algorithm: "ECC-P256"}

      assert {:ok, _} = CaConnectionManagement.connect(nil, ra.id, attrs)
      assert {:error, _} = CaConnectionManagement.connect(nil, ra.id, attrs)
    end
  end

  describe "disconnect/2" do
    test "revokes a connection" do
      ra = create_ra_instance!()
      attrs = %{issuer_key_id: "key-disc-#{System.unique_integer([:positive])}", algorithm: "ECC-P256"}
      {:ok, conn} = CaConnectionManagement.connect(nil, ra.id, attrs)

      assert {:ok, revoked} = CaConnectionManagement.disconnect(nil, conn.id)
      assert revoked.status == "revoked"
    end

    test "returns not_found for non-existent connection" do
      assert {:error, :not_found} = CaConnectionManagement.disconnect(nil, Uniq.UUID.uuid7())
    end
  end

  describe "list_connections/2" do
    test "lists active connections for an RA instance" do
      ra = create_ra_instance!()
      {:ok, _} = CaConnectionManagement.connect(nil, ra.id, %{issuer_key_id: "k1-#{System.unique_integer([:positive])}", algorithm: "ECC-P256"})
      {:ok, _} = CaConnectionManagement.connect(nil, ra.id, %{issuer_key_id: "k2-#{System.unique_integer([:positive])}", algorithm: "RSA-2048"})

      connections = CaConnectionManagement.list_connections(nil, ra.id)
      assert length(connections) == 2
    end

    test "does not include revoked connections" do
      ra = create_ra_instance!()
      {:ok, conn} = CaConnectionManagement.connect(nil, ra.id, %{issuer_key_id: "k-rev-#{System.unique_integer([:positive])}", algorithm: "ECC-P256"})
      CaConnectionManagement.disconnect(nil, conn.id)

      connections = CaConnectionManagement.list_connections(nil, ra.id)
      assert connections == []
    end
  end

  describe "list_connected_issuer_keys/1" do
    test "returns issuer key IDs for all active connections in tenant" do
      ra = create_ra_instance!()
      {:ok, _} = CaConnectionManagement.connect(nil, ra.id, %{issuer_key_id: "key-a", algorithm: "ECC-P256"})
      {:ok, _} = CaConnectionManagement.connect(nil, ra.id, %{issuer_key_id: "key-b", algorithm: "RSA-2048"})

      keys = CaConnectionManagement.list_connected_issuer_keys(nil)
      assert "key-a" in keys
      assert "key-b" in keys
    end
  end

  describe "has_connections?/1" do
    test "returns false when no connections exist" do
      refute CaConnectionManagement.has_connections?(nil)
    end

    test "returns true when at least one active connection exists" do
      ra = create_ra_instance!()
      {:ok, _} = CaConnectionManagement.connect(nil, ra.id, %{issuer_key_id: "k-exists", algorithm: "ECC-P256"})
      assert CaConnectionManagement.has_connections?(nil)
    end
  end
end
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
mix test test/pki_ra_engine/ca_connection_management_test.exs
```
Expected: FAIL — module not defined

- [ ] **Step 3: Write the implementation**

```elixir
defmodule PkiRaEngine.CaConnectionManagement do
  @moduledoc "Manages explicit RA-to-CA issuer key connections."

  import Ecto.Query
  alias PkiRaEngine.TenantRepo
  alias PkiRaEngine.Schema.RaCaConnection

  def connect(tenant_id, ra_instance_id, attrs) do
    repo = TenantRepo.ra_repo(tenant_id)

    %RaCaConnection{}
    |> RaCaConnection.changeset(
      Map.merge(attrs, %{
        ra_instance_id: ra_instance_id,
        connected_at: DateTime.utc_now() |> DateTime.truncate(:second)
      })
    )
    |> repo.insert()
  end

  def disconnect(tenant_id, connection_id) do
    repo = TenantRepo.ra_repo(tenant_id)

    case repo.get(RaCaConnection, connection_id) do
      nil -> {:error, :not_found}
      conn ->
        conn
        |> RaCaConnection.changeset(%{status: "revoked"})
        |> repo.update()
    end
  end

  def list_connections(tenant_id, ra_instance_id) do
    repo = TenantRepo.ra_repo(tenant_id)

    RaCaConnection
    |> where([c], c.ra_instance_id == ^ra_instance_id and c.status == "active")
    |> order_by([c], desc: c.connected_at)
    |> repo.all()
  end

  def list_connected_issuer_keys(tenant_id) do
    repo = TenantRepo.ra_repo(tenant_id)

    RaCaConnection
    |> where([c], c.status == "active")
    |> select([c], c.issuer_key_id)
    |> repo.all()
  end

  def has_connections?(tenant_id) do
    repo = TenantRepo.ra_repo(tenant_id)

    RaCaConnection
    |> where([c], c.status == "active")
    |> repo.aggregate(:count) > 0
  end

  def get_connection(tenant_id, connection_id) do
    repo = TenantRepo.ra_repo(tenant_id)

    case repo.get(RaCaConnection, connection_id) do
      nil -> {:error, :not_found}
      conn -> {:ok, conn}
    end
  end
end
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
mix test test/pki_ra_engine/ca_connection_management_test.exs
```
Expected: All pass

- [ ] **Step 5: Commit**

```bash
git add src/pki_ra_engine/lib/pki_ra_engine/ca_connection_management.ex \
        src/pki_ra_engine/test/pki_ra_engine/ca_connection_management_test.exs
git commit -m "feat(ra-engine): CA connection management module with tests"
```

---

### Task 3: CA Connection API Endpoints

**Files:**
- Create: `src/pki_ra_engine/lib/pki_ra_engine/api/ca_connection_controller.ex`
- Modify: `src/pki_ra_engine/lib/pki_ra_engine/api/authenticated_router.ex`

- [ ] **Step 1: Write the controller**

```elixir
defmodule PkiRaEngine.Api.CaConnectionController do
  @moduledoc "REST endpoints for RA-CA connection management."

  import Plug.Conn
  alias PkiRaEngine.CaConnectionManagement

  def index(conn) do
    tenant_id = conn.assigns[:tenant_id]
    ra_instance_id = conn.query_params["ra_instance_id"]

    connections =
      if ra_instance_id do
        CaConnectionManagement.list_connections(tenant_id, ra_instance_id)
      else
        []
      end

    json(conn, 200, Enum.map(connections, &serialize/1))
  end

  def create(conn) do
    tenant_id = conn.assigns[:tenant_id]
    ra_instance_id = conn.body_params["ra_instance_id"]

    attrs = %{
      issuer_key_id: conn.body_params["issuer_key_id"],
      issuer_key_name: conn.body_params["issuer_key_name"],
      algorithm: conn.body_params["algorithm"],
      ca_instance_name: conn.body_params["ca_instance_name"],
      connected_by: conn.body_params["connected_by"]
    }

    case CaConnectionManagement.connect(tenant_id, ra_instance_id, attrs) do
      {:ok, connection} ->
        json(conn, 201, serialize(connection))

      {:error, %Ecto.Changeset{} = changeset} ->
        json(conn, 422, %{error: "validation_error", details: changeset_errors(changeset)})
    end
  end

  def delete(conn, id) do
    tenant_id = conn.assigns[:tenant_id]

    case CaConnectionManagement.disconnect(tenant_id, id) do
      {:ok, connection} -> json(conn, 200, serialize(connection))
      {:error, :not_found} -> json(conn, 404, %{error: "not_found"})
    end
  end

  def connected_keys(conn) do
    tenant_id = conn.assigns[:tenant_id]
    keys = CaConnectionManagement.list_connected_issuer_keys(tenant_id)
    json(conn, 200, keys)
  end

  defp serialize(conn_record) do
    %{
      id: conn_record.id,
      ra_instance_id: conn_record.ra_instance_id,
      issuer_key_id: conn_record.issuer_key_id,
      issuer_key_name: conn_record.issuer_key_name,
      algorithm: conn_record.algorithm,
      ca_instance_name: conn_record.ca_instance_name,
      status: conn_record.status,
      connected_at: conn_record.connected_at && DateTime.to_iso8601(conn_record.connected_at),
      connected_by: conn_record.connected_by,
      inserted_at: conn_record.inserted_at,
      updated_at: conn_record.updated_at
    }
  end

  defp changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end

  defp json(conn, status, body) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(body))
  end
end
```

- [ ] **Step 2: Add routes to authenticated_router.ex**

Add these routes inside the authenticated router, in a new `# --- CA connection routes ---` section before the `match _` clause:

```elixir
  # --- CA connection routes ---

  get "/ca-connections" do
    conn |> RbacPlug.call(:manage_ra_admins) |> dispatch_unless_halted(&CaConnectionController.index/1)
  end

  post "/ca-connections" do
    conn |> RbacPlug.call(:manage_ra_admins) |> dispatch_unless_halted(&CaConnectionController.create/1)
  end

  delete "/ca-connections/:id" do
    conn |> RbacPlug.call(:manage_ra_admins) |> dispatch_unless_halted(&CaConnectionController.delete(&1, id))
  end

  get "/ca-connections/keys" do
    conn |> RbacPlug.call(:manage_ra_admins) |> dispatch_unless_halted(&CaConnectionController.connected_keys/1)
  end
```

Also add `CaConnectionController` to the alias block at the top.

- [ ] **Step 3: Compile and verify**

```bash
mix compile
```
Expected: No errors

- [ ] **Step 4: Commit**

```bash
git add src/pki_ra_engine/lib/pki_ra_engine/api/ca_connection_controller.ex \
        src/pki_ra_engine/lib/pki_ra_engine/api/authenticated_router.ex
git commit -m "feat(ra-engine): CA connection REST endpoints with RBAC"
```

---

## Phase 2: Portal — Sidebar Redesign

### Task 4: Grouped Sidebar with Role-Based Visibility

**Files:**
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/components/layouts.ex`

- [ ] **Step 1: Rewrite the sidebar navigation**

Replace the flat nav list in the `app/1` function with grouped sections. The sidebar must receive `current_user` with a `role` field and conditionally render sections.

The key changes:
- Add section headers (non-clickable labels): OVERVIEW, OPERATIONS, CONFIGURATION, ADMINISTRATION
- Add `role` checks: RA Admin sees all, RA Officer sees OVERVIEW + OPERATIONS + My Profile, Auditor sees OVERVIEW + Audit Log + My Profile
- Add new "CA Connection" link under CONFIGURATION
- Reorder items to match the spec grouping

Replace the `<nav>` block (lines 41-53) with:

```elixir
<nav class="flex-1 px-2 py-3 space-y-1 overflow-y-auto">
  <%!-- OVERVIEW --%>
  <.sidebar_section label="OVERVIEW">
    <.sidebar_link href="/" icon="hero-home" label="Dashboard" current={@page_title} />
  </.sidebar_section>

  <%!-- OPERATIONS — visible to ra_admin and ra_officer --%>
  <.sidebar_section :if={user_role(@current_user) in ["ra_admin", "ra_officer"]} label="OPERATIONS">
    <.sidebar_link href="/csrs" icon="hero-document-check" label="CSR Management" current={@page_title} />
    <.sidebar_link href="/certificates" icon="hero-document-check" label="Certificates" current={@page_title} />
    <.sidebar_link href="/validation" icon="hero-shield-check" label="Validation Services" current={@page_title} />
  </.sidebar_section>

  <%!-- CONFIGURATION — ra_admin only --%>
  <.sidebar_section :if={user_role(@current_user) == "ra_admin"} label="CONFIGURATION">
    <.sidebar_link href="/cert-profiles" icon="hero-clipboard-document-list" label="Certificate Profiles" current={@page_title} />
    <.sidebar_link href="/ca-connection" icon="hero-link" label="CA Connection" current={@page_title} />
    <.sidebar_link href="/service-configs" icon="hero-cog-6-tooth" label="Service Configs" current={@page_title} />
  </.sidebar_section>

  <%!-- ADMINISTRATION — ra_admin sees all, auditor sees only Audit Log --%>
  <.sidebar_section :if={user_role(@current_user) in ["ra_admin", "auditor"]} label="ADMINISTRATION">
    <.sidebar_link :if={user_role(@current_user) == "ra_admin"} href="/users" icon="hero-users" label="Users" current={@page_title} />
    <.sidebar_link :if={user_role(@current_user) == "ra_admin"} href="/api-keys" icon="hero-key" label="API Keys" current={@page_title} />
    <.sidebar_link :if={user_role(@current_user) == "ra_admin"} href="/ra-instances" icon="hero-server" label="RA Instances" current={@page_title} />
    <.sidebar_link href="/audit-log" icon="hero-document-text" label="Audit Log" current={@page_title} />
  </.sidebar_section>

  <div class="divider my-1 px-3"></div>
  <.sidebar_link href="/profile" icon="hero-user-circle" label="My Profile" current={@page_title} />
</nav>
```

- [ ] **Step 2: Add helper components**

Add the `sidebar_section` component and `user_role` helper to `layouts.ex`:

```elixir
attr :label, :string, required: true
slot :inner_block, required: true

defp sidebar_section(assigns) do
  ~H"""
  <div class="pt-3 first:pt-0">
    <p class="px-3 pb-1 text-[10px] font-bold uppercase tracking-wider text-base-content/30">{@label}</p>
    <div class="space-y-0.5">
      {render_slot(@inner_block)}
    </div>
  </div>
  """
end

defp user_role(nil), do: nil
defp user_role(user), do: user[:role] || user["role"]
```

- [ ] **Step 3: Update `is_active?/2` to handle new labels**

Add these clauses:

```elixir
defp is_active?("CSR Management", page) when page in ["CSRs", "CSR Management"], do: true
defp is_active?("Validation Services", page) when page in ["Validation", "Validation Services"], do: true
defp is_active?("Certificate Profiles", page) when page in ["Cert Profiles", "Certificate Profiles"], do: true
defp is_active?("CA Connection", "CA Connection"), do: true
defp is_active?("My Profile", "Profile"), do: true
```

- [ ] **Step 4: Compile and check in browser**

```bash
cd src/pki_ra_portal && mix compile
```
Expected: No errors

- [ ] **Step 5: Commit**

```bash
git add src/pki_ra_portal/lib/pki_ra_portal_web/components/layouts.ex
git commit -m "feat(ra-portal): grouped sidebar with role-based visibility"
```

---

## Phase 3: Portal — Welcome Screen + Setup Wizard

### Task 5: Welcome Screen LiveView

**Files:**
- Create: `src/pki_ra_portal/lib/pki_ra_portal_web/live/welcome_live.ex`
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/router.ex`

- [ ] **Step 1: Write the welcome screen LiveView**

Full-page layout (no sidebar). Shows RA instance name, welcome message, two buttons.

```elixir
defmodule PkiRaPortalWeb.WelcomeLive do
  use PkiRaPortalWeb, :live_view

  alias PkiRaPortal.RaEngineClient

  @impl true
  def mount(_params, _session, socket) do
    # Check if setup is actually needed
    has_connections = check_has_connections(socket)
    has_profiles = check_has_profiles(socket)

    if has_connections and has_profiles do
      # Already set up — redirect to dashboard
      {:ok, push_navigate(socket, to: "/")}
    else
      ra_instances = case RaEngineClient.list_ra_instances(tenant_opts(socket)) do
        {:ok, instances} -> instances
        _ -> []
      end

      ra_name = case ra_instances do
        [first | _] -> first[:name] || first["name"] || "Registration Authority"
        _ -> "Registration Authority"
      end

      {:ok,
       assign(socket,
         page_title: "Welcome",
         ra_name: ra_name,
         layout: false
       )}
    end
  end

  defp check_has_connections(socket) do
    case RaEngineClient.list_ca_connections([], tenant_opts(socket)) do
      {:ok, conns} -> length(conns) > 0
      _ -> false
    end
  end

  defp check_has_profiles(socket) do
    case RaEngineClient.list_cert_profiles(tenant_opts(socket)) do
      {:ok, profiles} -> length(profiles) > 0
      _ -> false
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="min-h-screen bg-base-200 flex items-center justify-center">
      <div class="card bg-base-100 shadow-xl max-w-lg w-full mx-4">
        <div class="card-body text-center">
          <div class="flex justify-center mb-4">
            <div class="flex items-center justify-center w-16 h-16 rounded-2xl bg-primary/10">
              <.icon name="hero-shield-check" class="size-8 text-primary" />
            </div>
          </div>
          <h1 class="text-2xl font-bold">{@ra_name}</h1>
          <p class="text-base-content/60 mt-2">
            Let's configure your Registration Authority. This will take a few minutes.
          </p>
          <div class="mt-8 space-y-3">
            <a href="/setup-wizard" class="btn btn-primary btn-block">Start Setup</a>
            <a href="/" class="btn btn-ghost btn-sm text-base-content/50">
              Skip, I'll configure manually
            </a>
          </div>
        </div>
      </div>
    </div>
    """
  end
end
```

- [ ] **Step 2: Add route and first-login redirect**

In `router.ex`, add inside the `live_session :authenticated` block:

```elixir
live "/welcome", WelcomeLive
live "/setup-wizard", SetupWizardLive
live "/ca-connection", CaConnectionLive
```

- [ ] **Step 3: Add first-login detection to AuthHook**

In `auth_hook.ex`, after the user is loaded into assigns, add a check: if user's `must_change_password` was just cleared (first real login) AND no CA connections AND no cert profiles exist, redirect to `/welcome`. This check should only fire for `ra_admin` role.

Add after the `assign(socket, :current_user, user)` line:

```elixir
# First-login redirect for ra_admin (only on non-setup pages)
if user[:role] == "ra_admin" and
   socket.view not in [PkiRaPortalWeb.WelcomeLive, PkiRaPortalWeb.SetupWizardLive, PkiRaPortalWeb.ProfileLive] and
   needs_setup?(socket) do
  {:halt, push_navigate(socket, to: "/welcome")}
else
  {:cont, socket}
end
```

Where `needs_setup?/1` checks for zero CA connections and zero cert profiles (same logic as WelcomeLive mount).

- [ ] **Step 4: Compile and verify**

```bash
mix compile
```

- [ ] **Step 5: Commit**

```bash
git add src/pki_ra_portal/lib/pki_ra_portal_web/live/welcome_live.ex \
        src/pki_ra_portal/lib/pki_ra_portal_web/router.ex \
        src/pki_ra_portal/lib/pki_ra_portal_web/live/auth_hook.ex
git commit -m "feat(ra-portal): welcome screen with first-login redirect"
```

---

### Task 6: Setup Wizard LiveView

**Files:**
- Create: `src/pki_ra_portal/lib/pki_ra_portal_web/live/setup_wizard_live.ex`

- [ ] **Step 1: Write the wizard LiveView**

This is a multi-step LiveView with `@step` assign (1-5). Each step renders a different form. Full-page layout, no sidebar. Step indicator at top.

The wizard is large — implement it as a single LiveView with a `render_step/1` function that pattern-matches on `@step`. Each step's form submits an event that processes the data and advances to the next step.

Key events:
- `"connect_ca_key"` — Step 1: connect an issuer key
- `"create_profile"` — Step 2: create cert profile from template
- `"invite_user"` — Step 3: add team member
- `"configure_service"` — Step 4: configure service
- `"create_api_key"` — Step 5: create API key
- `"next_step"` — advance to next step
- `"skip_step"` — skip current step (steps 3-5 only)
- `"finish"` — go to dashboard

Mount loads available issuer keys from CA Engine and RA instances. Each step shows the relevant form inline, with results displayed below (e.g., "Connected: ECC-P256 key from Test CA").

This is the largest single file. Target ~400 lines with render helpers.

- [ ] **Step 2: Compile and test manually**

```bash
mix compile
```

Navigate to `/setup-wizard` in browser. Walk through all 5 steps.

- [ ] **Step 3: Commit**

```bash
git add src/pki_ra_portal/lib/pki_ra_portal_web/live/setup_wizard_live.ex
git commit -m "feat(ra-portal): 5-step setup wizard for first-time RA configuration"
```

---

### Task 7: CA Connection LiveView (standalone page)

**Files:**
- Create: `src/pki_ra_portal/lib/pki_ra_portal_web/live/ca_connection_live.ex`
- Modify: `src/pki_ra_portal/lib/pki_ra_portal/ra_engine_client.ex` — add callbacks
- Modify: `src/pki_ra_portal/lib/pki_ra_portal/ra_engine_client/direct.ex` — implement

- [ ] **Step 1: Add client callbacks**

In `ra_engine_client.ex`, add:

```elixir
@callback list_ca_connections(keyword(), keyword()) :: {:ok, [map()]} | {:error, term()}
@callback create_ca_connection(map(), keyword()) :: {:ok, map()} | {:error, term()}
@callback delete_ca_connection(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
```

And corresponding public functions:

```elixir
def list_ca_connections(filters \\ [], opts \\ []), do: impl().list_ca_connections(filters, opts)
def create_ca_connection(attrs, opts \\ []), do: impl().create_ca_connection(attrs, opts)
def delete_ca_connection(id, opts \\ []), do: impl().delete_ca_connection(id, opts)
```

- [ ] **Step 2: Implement in direct.ex**

```elixir
@impl true
def list_ca_connections(_filters, opts \\ []) do
  tenant_id = opts[:tenant_id]
  # Get first RA instance for this tenant
  case PkiRaEngine.RaInstanceManagement.list_ra_instances(tenant_id) do
    [ra | _] ->
      connections = PkiRaEngine.CaConnectionManagement.list_connections(tenant_id, ra.id)
      {:ok, Enum.map(connections, &connection_to_map/1)}
    _ ->
      {:ok, []}
  end
end

@impl true
def create_ca_connection(attrs, opts \\ []) do
  tenant_id = opts[:tenant_id]
  case PkiRaEngine.RaInstanceManagement.list_ra_instances(tenant_id) do
    [ra | _] ->
      case PkiRaEngine.CaConnectionManagement.connect(tenant_id, ra.id, attrs) do
        {:ok, conn} -> {:ok, connection_to_map(conn)}
        {:error, _} = err -> err
      end
    _ ->
      {:error, :no_ra_instance}
  end
end

@impl true
def delete_ca_connection(id, opts \\ []) do
  tenant_id = opts[:tenant_id]
  case PkiRaEngine.CaConnectionManagement.disconnect(tenant_id, id) do
    {:ok, conn} -> {:ok, connection_to_map(conn)}
    {:error, _} = err -> err
  end
end

defp connection_to_map(conn) do
  %{
    id: conn.id,
    ra_instance_id: conn.ra_instance_id,
    issuer_key_id: conn.issuer_key_id,
    issuer_key_name: conn.issuer_key_name,
    algorithm: conn.algorithm,
    ca_instance_name: conn.ca_instance_name,
    status: conn.status,
    connected_at: conn.connected_at
  }
end
```

- [ ] **Step 3: Write the CA Connection LiveView**

The page shows:
- Connected keys table (with disconnect button)
- Available keys from CA Engine (with connect button)
- Error handling for CA Engine unreachable

```elixir
defmodule PkiRaPortalWeb.CaConnectionLive do
  use PkiRaPortalWeb, :live_view
  require Logger
  alias PkiRaPortal.RaEngineClient

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_data)

    {:ok,
     assign(socket,
       page_title: "CA Connection",
       connections: [],
       available_keys: [],
       loading: true,
       error: nil
     )}
  end

  @impl true
  def handle_info(:load_data, socket) do
    opts = tenant_opts(socket)

    connections = case RaEngineClient.list_ca_connections([], opts) do
      {:ok, conns} -> conns
      {:error, _} -> []
    end

    available_keys = case RaEngineClient.available_issuer_keys(opts) do
      {:ok, keys} -> keys
      {:error, reason} ->
        Logger.error("ca_connection_keys_unavailable reason=#{inspect(reason)}")
        []
    end

    # Filter out already-connected keys
    connected_ids = MapSet.new(connections, & &1[:issuer_key_id])
    unconnected_keys = Enum.reject(available_keys, & MapSet.member?(connected_ids, &1["id"] || &1[:id]))

    {:noreply,
     assign(socket,
       connections: connections,
       available_keys: unconnected_keys,
       loading: false
     )}
  end

  @impl true
  def handle_event("connect_key", %{"key_id" => key_id, "key_name" => key_name, "algorithm" => algo, "ca_name" => ca_name}, socket) do
    opts = tenant_opts(socket)
    attrs = %{
      issuer_key_id: key_id,
      issuer_key_name: key_name,
      algorithm: algo,
      ca_instance_name: ca_name,
      connected_by: socket.assigns.current_user[:id] || socket.assigns.current_user["id"]
    }

    case RaEngineClient.create_ca_connection(attrs, opts) do
      {:ok, _conn} ->
        send(self(), :load_data)
        {:noreply, put_flash(socket, :info, "Connected to #{key_name} (#{algo})")}
      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to connect: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("disconnect_key", %{"id" => id}, socket) do
    opts = tenant_opts(socket)
    case RaEngineClient.delete_ca_connection(id, opts) do
      {:ok, _} ->
        send(self(), :load_data)
        {:noreply, put_flash(socket, :info, "Connection revoked")}
      {:error, _} ->
        {:noreply, put_flash(socket, :error, "Failed to disconnect")}
    end
  end

  # render/1 shows two sections:
  # 1. Connected Keys table with disconnect buttons
  # 2. Available Keys cards with connect buttons
  # Handle loading and empty states
  @impl true
  def render(assigns) do
    ~H"""
    <div class="space-y-6">
      <h1 class="text-2xl font-bold tracking-tight">CA Connection</h1>

      <div class="alert alert-info shadow-sm">
        <.icon name="hero-information-circle" class="size-5 shrink-0" />
        <span class="text-sm">
          Connect your RA to CA issuer keys. Only connected keys can be used in certificate profiles.
        </span>
      </div>

      <%!-- Connected Keys --%>
      <section class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <h2 class="card-title text-sm font-semibold uppercase tracking-wide text-base-content/60">Connected Keys</h2>
          <%= if @loading do %>
            <div class="flex items-center gap-2 mt-2">
              <span class="loading loading-spinner loading-sm"></span>
              <span class="text-sm text-base-content/50">Loading...</span>
            </div>
          <% else %>
            <%= if @connections == [] do %>
              <p class="text-sm text-base-content/50 mt-2">No CA keys connected yet. Connect a key below to start issuing certificates.</p>
            <% else %>
              <table class="table table-sm mt-2">
                <thead>
                  <tr class="border-base-300">
                    <th>Key Name</th>
                    <th>Algorithm</th>
                    <th>CA Instance</th>
                    <th>Connected</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  <tr :for={conn <- @connections} class="hover:bg-base-200/50">
                    <td class="font-medium">{conn[:issuer_key_name] || conn[:issuer_key_id]}</td>
                    <td><span class="badge badge-sm badge-outline">{conn[:algorithm]}</span></td>
                    <td class="text-sm text-base-content/60">{conn[:ca_instance_name]}</td>
                    <td class="text-xs text-base-content/50">{conn[:connected_at]}</td>
                    <td>
                      <button
                        phx-click="disconnect_key"
                        phx-value-id={conn[:id]}
                        class="btn btn-ghost btn-xs text-error"
                        data-confirm="Disconnect this CA key? Existing cert profiles using it will not be affected."
                      >
                        Disconnect
                      </button>
                    </td>
                  </tr>
                </tbody>
              </table>
            <% end %>
          <% end %>
        </div>
      </section>

      <%!-- Available Keys from CA Engine --%>
      <section class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <h2 class="card-title text-sm font-semibold uppercase tracking-wide text-base-content/60">Available CA Keys</h2>
          <%= if @loading do %>
            <div class="flex items-center gap-2 mt-2">
              <span class="loading loading-spinner loading-sm"></span>
              <span class="text-sm text-base-content/50">Querying CA Engine...</span>
            </div>
          <% else %>
            <%= if @available_keys == [] do %>
              <p class="text-sm text-base-content/50 mt-2">
                No additional CA keys available. All keys are either connected or no leaf issuer keys exist on the CA Engine.
              </p>
            <% else %>
              <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 mt-2">
                <div :for={key <- @available_keys} class="card card-compact bg-base-200/50 border border-base-300">
                  <div class="card-body">
                    <h3 class="font-medium text-sm">{key["name"] || key[:name] || key["id"] || key[:id]}</h3>
                    <div class="flex gap-2">
                      <span class="badge badge-sm badge-primary badge-outline">{key["algorithm"] || key[:algorithm]}</span>
                      <span class="text-xs text-base-content/50">{key["ca_instance_name"] || key[:ca_instance_name]}</span>
                    </div>
                    <div class="card-actions justify-end mt-2">
                      <button
                        phx-click="connect_key"
                        phx-value-key_id={key["id"] || key[:id]}
                        phx-value-key_name={key["name"] || key[:name]}
                        phx-value-algorithm={key["algorithm"] || key[:algorithm]}
                        phx-value-ca_name={key["ca_instance_name"] || key[:ca_instance_name]}
                        class="btn btn-primary btn-xs"
                      >
                        Connect
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            <% end %>
          <% end %>
        </div>
      </section>
    </div>
    """
  end
end
```

- [ ] **Step 4: Compile and verify**

```bash
mix compile
```

- [ ] **Step 5: Commit**

```bash
git add src/pki_ra_portal/lib/pki_ra_portal/ra_engine_client.ex \
        src/pki_ra_portal/lib/pki_ra_portal/ra_engine_client/direct.ex \
        src/pki_ra_portal/lib/pki_ra_portal_web/live/ca_connection_live.ex
git commit -m "feat(ra-portal): CA Connection page with connect/disconnect"
```

---

## Phase 4: Portal — Role-Adaptive Dashboard

### Task 8: Rewrite Dashboard LiveView

**Files:**
- Rewrite: `src/pki_ra_portal/lib/pki_ra_portal_web/live/dashboard_live.ex`

- [ ] **Step 1: Rewrite dashboard with role-adaptive rendering**

The dashboard mount loads data based on role, then `render/1` delegates to role-specific render functions.

Key structure:
```elixir
def mount(_params, _session, socket) do
  if connected?(socket), do: send(self(), :load_data)
  role = get_role(socket)
  {:ok, assign(socket, page_title: "Dashboard", role: role, loading: true, ...)}
end

def handle_info(:load_data, socket) do
  case socket.assigns.role do
    "ra_admin" -> load_admin_data(socket)
    "ra_officer" -> load_officer_data(socket)
    "auditor" -> load_auditor_data(socket)
    _ -> {:noreply, assign(socket, loading: false)}
  end
end

def render(assigns) do
  ~H"""
  <div class="space-y-6">
    <h1 class="text-2xl font-bold tracking-tight">Dashboard</h1>
    <%= case @role do %>
      <% "ra_admin" -> %> <.admin_dashboard {assigns} />
      <% "ra_officer" -> %> <.officer_dashboard {assigns} />
      <% "auditor" -> %> <.auditor_dashboard {assigns} />
      <% _ -> %> <p>Unknown role.</p>
    <% end %>
  </div>
  """
end
```

Admin dashboard includes: system health cards, setup completeness (conditional), attention required alerts, team activity feed.

Officer dashboard: my queue card, DCV pending, recent actions, quick stats.

Auditor dashboard: recent activity feed, compliance alerts, quick filter links.

Each section is a function component to keep `render/1` clean.

- [ ] **Step 2: Compile and verify each role view**

```bash
mix compile
```

Test by logging in with different roles and verifying the correct dashboard renders.

- [ ] **Step 3: Commit**

```bash
git add src/pki_ra_portal/lib/pki_ra_portal_web/live/dashboard_live.ex
git commit -m "feat(ra-portal): role-adaptive dashboard — admin, officer, auditor views"
```

---

## Phase 5: Portal — Cert Profile Template Picker

### Task 9: Template Picker in Cert Profile Creation

**Files:**
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/live/cert_profiles_live.ex`

- [ ] **Step 1: Add template selection to create flow**

Add a `@templates` module attribute with the 5 template definitions (TLS Server, TLS Client, Code Signing, Email/S-MIME, Custom).

When the admin clicks "Create Profile", show a template picker modal first. Selecting a template pre-fills the form fields. The form includes a new "Issuer Key" dropdown populated from `RaEngineClient.list_ca_connections/2` (only active connections).

Key changes:
- Add `show_template_picker` assign (boolean)
- Add `selected_template` assign
- Add `connected_keys` assign (loaded on mount)
- Event `"select_template"` — picks template, pre-fills form, hides picker
- Modify `"create_profile"` event — include `issuer_key_id` from dropdown
- Add issuer key dropdown to the create/edit form

- [ ] **Step 2: Compile and verify**

```bash
mix compile
```

- [ ] **Step 3: Commit**

```bash
git add src/pki_ra_portal/lib/pki_ra_portal_web/live/cert_profiles_live.ex
git commit -m "feat(ra-portal): cert profile template picker with issuer key dropdown"
```

---

## Phase 6: Integration Testing

### Task 10: End-to-End Wizard Flow Test

**Files:**
- Create: `src/pki_ra_engine/test/pki_ra_engine/ca_connection_management_test.exs` (already in Task 2)

- [ ] **Step 1: Run full test suite**

```bash
cd src/pki_ra_engine && mix test --seed 0
```
Expected: All pass including new CA connection tests

- [ ] **Step 2: Compile portal**

```bash
cd src/pki_ra_portal && mix compile
```
Expected: No errors

- [ ] **Step 3: Manual smoke test**

1. Log in as RA admin (fresh account)
2. Verify welcome screen appears
3. Click "Start Setup"
4. Step 1: Connect to a CA key
5. Step 2: Create a TLS Server profile using template
6. Step 3: Skip (or invite a user)
7. Step 4: Skip
8. Step 5: Skip
9. Verify dashboard shows setup completeness
10. Verify sidebar shows grouped navigation
11. Log in as RA officer — verify officer dashboard and limited sidebar
12. Log in as auditor — verify auditor dashboard and audit-only sidebar

- [ ] **Step 4: Final commit**

```bash
git add -A
git commit -m "feat(ra-portal): complete UX redesign — wizard, dashboard, sidebar"
```

---

## Summary

| Phase | Tasks | Description |
|-------|-------|-------------|
| 1 | 1-3 | Engine: ra_ca_connections schema, management module, REST API |
| 2 | 4 | Portal: Grouped sidebar with role visibility |
| 3 | 5-6 | Portal: Welcome screen + 5-step setup wizard |
| 4 | 7 | Portal: CA Connection standalone page |
| 5 | 8 | Portal: Role-adaptive dashboard (admin/officer/auditor) |
| 6 | 9 | Portal: Cert profile template picker |
| 7 | 10 | Integration testing and smoke test |
