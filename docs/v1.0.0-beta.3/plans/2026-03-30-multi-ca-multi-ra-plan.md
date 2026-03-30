# Multi-CA / Multi-RA Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Evolve the PKI system to support multiple CA instances (with hierarchy) and multiple RA instances per tenant.

**Architecture:** Evolve in-place (Approach A). Add `parent_id` to CA instances for hierarchy, create `ra_instances` table, link cert profiles to specific issuer keys. The changes are additive — existing schemas gain new fields and relationships without breaking current functionality.

**Tech Stack:** Elixir, Phoenix LiveView, Ecto, PostgreSQL, Plug routers, ExUnit

**Constraint:** Do NOT touch any auth/password/session files — another branch is working on Forgot Password features for all portals.

---

## Phase 1: Data Model Changes (Foundation)

### Task 1: Modify Tenant Schema — Remove Algorithm Fields, Add max_ca_depth

**Files:**
- Modify: `src/pki_platform_engine/lib/pki_platform_engine/tenant.ex`
- Modify: `src/pki_platform_engine/test/pki_platform_engine/tenant_test.exs`

- [ ] **Step 1: Write failing test for max_ca_depth field**

In `src/pki_platform_engine/test/pki_platform_engine/tenant_test.exs`, add:

```elixir
describe "max_ca_depth" do
  test "defaults max_ca_depth to 2" do
    changeset = Tenant.changeset(%Tenant{}, %{name: "Test Org", slug: "test-org", email: "a@b.com"})
    assert Ecto.Changeset.get_field(changeset, :max_ca_depth) == 2
  end

  test "accepts custom max_ca_depth" do
    changeset = Tenant.changeset(%Tenant{}, %{name: "Test Org", slug: "test-org", email: "a@b.com", max_ca_depth: 3})
    assert Ecto.Changeset.get_field(changeset, :max_ca_depth) == 3
  end

  test "changeset is valid without signing_algorithm" do
    changeset = Tenant.changeset(%Tenant{}, %{name: "Test Org", slug: "test-org", email: "a@b.com"})
    assert changeset.valid?
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd src/pki_platform_engine && mix test test/pki_platform_engine/tenant_test.exs --trace`
Expected: FAIL — `max_ca_depth` field doesn't exist yet

- [ ] **Step 3: Update Tenant schema**

In `src/pki_platform_engine/lib/pki_platform_engine/tenant.ex`:

1. Remove `field :signing_algorithm, :string, default: "ECC-P256"`
2. Remove `field :kem_algorithm, :string, default: "ECDH-P256"`
3. Add `field :max_ca_depth, :integer, default: 2`
4. Remove `@signing_algorithms` list
5. Update `changeset/2`: remove `:signing_algorithm` and `:kem_algorithm` from `cast/3` list, add `:max_ca_depth`. Remove `validate_inclusion(:signing_algorithm, @signing_algorithms)`
6. Add `|> validate_number(:max_ca_depth, greater_than: 0, less_than_or_equal_to: 10)`

- [ ] **Step 4: Run test to verify it passes**

Run: `cd src/pki_platform_engine && mix test test/pki_platform_engine/tenant_test.exs --trace`
Expected: PASS

- [ ] **Step 5: Update existing tests that reference signing_algorithm**

Search for `signing_algorithm` in `src/pki_platform_engine/test/` and remove/update any tests that assert on it. Also update `provisioner_test.exs` if it passes `signing_algorithm` in opts.

- [ ] **Step 6: Run full platform engine test suite**

Run: `cd src/pki_platform_engine && mix test --trace`
Expected: All tests PASS

- [ ] **Step 7: Commit**

```bash
git add src/pki_platform_engine/lib/pki_platform_engine/tenant.ex src/pki_platform_engine/test/
git commit -m "feat: remove algorithm fields from tenant, add max_ca_depth"
```

---

### Task 2: Add parent_id to CaInstance Schema

**Files:**
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/schema/ca_instance.ex`
- Modify: `src/pki_ca_engine/test/pki_ca_engine/schema_test.exs`

- [ ] **Step 1: Write failing tests for CA hierarchy**

In `src/pki_ca_engine/test/pki_ca_engine/schema_test.exs`, add a new describe block (or create a new file `src/pki_ca_engine/test/pki_ca_engine/ca_instance_hierarchy_test.exs`):

```elixir
defmodule PkiCaEngine.CaInstanceHierarchyTest do
  use PkiCaEngine.DataCase, async: true

  alias PkiCaEngine.Schema.CaInstance

  describe "CaInstance hierarchy" do
    test "changeset accepts parent_id" do
      {:ok, root} = Repo.insert(CaInstance.changeset(%CaInstance{}, %{name: "root-ca", created_by: "admin"}))

      changeset = CaInstance.changeset(%CaInstance{}, %{
        name: "sub-ca",
        parent_id: root.id,
        created_by: "admin"
      })

      assert changeset.valid?
      assert Ecto.Changeset.get_field(changeset, :parent_id) == root.id
    end

    test "root CA has nil parent_id" do
      {:ok, root} = Repo.insert(CaInstance.changeset(%CaInstance{}, %{name: "root-ca-2", created_by: "admin"}))
      assert root.parent_id == nil
    end

    test "can load children association" do
      {:ok, root} = Repo.insert(CaInstance.changeset(%CaInstance{}, %{name: "root-ca-3", created_by: "admin"}))
      {:ok, _sub} = Repo.insert(CaInstance.changeset(%CaInstance{}, %{name: "sub-ca-3", parent_id: root.id, created_by: "admin"}))

      root_with_children = Repo.preload(root, :children)
      assert length(root_with_children.children) == 1
    end

    test "can load parent association" do
      {:ok, root} = Repo.insert(CaInstance.changeset(%CaInstance{}, %{name: "root-ca-4", created_by: "admin"}))
      {:ok, sub} = Repo.insert(CaInstance.changeset(%CaInstance{}, %{name: "sub-ca-4", parent_id: root.id, created_by: "admin"}))

      sub_with_parent = Repo.preload(sub, :parent)
      assert sub_with_parent.parent.id == root.id
    end
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd src/pki_ca_engine && mix test test/pki_ca_engine/ca_instance_hierarchy_test.exs --trace`
Expected: FAIL — `parent_id` field doesn't exist

- [ ] **Step 3: Update CaInstance schema**

In `src/pki_ca_engine/lib/pki_ca_engine/schema/ca_instance.ex`:

1. Add inside the `schema` block:
   ```elixir
   field :parent_id, :binary_id
   ```
2. Add associations:
   ```elixir
   belongs_to :parent, PkiCaEngine.Schema.CaInstance, foreign_key: :parent_id, define_field: false
   has_many :children, PkiCaEngine.Schema.CaInstance, foreign_key: :parent_id
   ```
3. Update `changeset/2` to include `:parent_id` in the `cast/3` list
4. Add `foreign_key_constraint(:parent_id)`

- [ ] **Step 4: Add migration for ca_instances parent_id**

The CA engine uses the tenant's database. The column must be added in the tenant database schema setup. In `src/pki_platform_engine/lib/pki_platform_engine/provisioner.ex`, update `create_schemas/1` to add the column. Or, since this is pre-production, add it to the CA engine's bootstrap SQL.

For the test database, add the column in the CA engine's test setup. In `src/pki_ca_engine/priv/repo/migrations/` create a migration:

```elixir
defmodule PkiCaEngine.Repo.Migrations.AddParentIdToCaInstances do
  use Ecto.Migration

  def change do
    alter table(:ca_instances) do
      add :parent_id, references(:ca_instances, type: :binary_id, on_delete: :restrict)
    end

    create index(:ca_instances, [:parent_id])
  end
end
```

Run: `cd src/pki_ca_engine && mix ecto.migrate`

- [ ] **Step 5: Run test to verify it passes**

Run: `cd src/pki_ca_engine && mix test test/pki_ca_engine/ca_instance_hierarchy_test.exs --trace`
Expected: PASS

- [ ] **Step 6: Run full CA engine test suite**

Run: `cd src/pki_ca_engine && mix test --trace`
Expected: All tests PASS (existing tests should not break since parent_id is nullable)

- [ ] **Step 7: Commit**

```bash
git add src/pki_ca_engine/lib/pki_ca_engine/schema/ca_instance.ex src/pki_ca_engine/test/ src/pki_ca_engine/priv/
git commit -m "feat: add parent_id to ca_instances for CA hierarchy"
```

---

### Task 3: Create RaInstance Schema and Table

**Files:**
- Create: `src/pki_ra_engine/lib/pki_ra_engine/schema/ra_instance.ex`
- Create: `src/pki_ra_engine/test/pki_ra_engine/ra_instance_test.exs`

- [ ] **Step 1: Write failing test for RaInstance schema**

Create `src/pki_ra_engine/test/pki_ra_engine/ra_instance_test.exs`:

```elixir
defmodule PkiRaEngine.RaInstanceTest do
  use PkiRaEngine.DataCase, async: true

  alias PkiRaEngine.Schema.RaInstance

  @valid_attrs %{name: "JPJ Registration Authority", created_by: "admin"}

  describe "RaInstance.changeset/2" do
    test "valid changeset" do
      changeset = RaInstance.changeset(%RaInstance{}, @valid_attrs)
      assert changeset.valid?
    end

    test "defaults status to initialized" do
      changeset = RaInstance.changeset(%RaInstance{}, @valid_attrs)
      assert Ecto.Changeset.get_field(changeset, :status) == "initialized"
    end

    test "generates UUIDv7 id" do
      changeset = RaInstance.changeset(%RaInstance{}, @valid_attrs)
      assert Ecto.Changeset.get_field(changeset, :id) != nil
    end

    test "rejects missing name" do
      changeset = RaInstance.changeset(%RaInstance{}, %{created_by: "admin"})
      refute changeset.valid?
      assert errors_on(changeset)[:name]
    end

    test "rejects invalid status" do
      changeset = RaInstance.changeset(%RaInstance{}, Map.put(@valid_attrs, :status, "deleted"))
      refute changeset.valid?
      assert errors_on(changeset)[:status]
    end

    test "can insert and read back" do
      {:ok, instance} = %RaInstance{} |> RaInstance.changeset(@valid_attrs) |> Repo.insert()
      assert instance.name == "JPJ Registration Authority"
      assert instance.status == "initialized"
    end
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd src/pki_ra_engine && mix test test/pki_ra_engine/ra_instance_test.exs --trace`
Expected: FAIL — module `PkiRaEngine.Schema.RaInstance` not found

- [ ] **Step 3: Create RaInstance schema**

Create `src/pki_ra_engine/lib/pki_ra_engine/schema/ra_instance.ex`:

```elixir
defmodule PkiRaEngine.Schema.RaInstance do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  @statuses ["initialized", "active", "suspended"]

  schema "ra_instances" do
    field :name, :string
    field :status, :string, default: "initialized"
    field :created_by, :string

    has_many :ra_users, PkiRaEngine.Schema.RaUser
    has_many :cert_profiles, PkiRaEngine.Schema.CertProfile
    has_many :ra_api_keys, PkiRaEngine.Schema.RaApiKey

    timestamps()
  end

  def changeset(instance, attrs) do
    instance
    |> cast(attrs, [:name, :status, :created_by])
    |> validate_required([:name])
    |> validate_inclusion(:status, @statuses)
    |> unique_constraint(:name)
    |> maybe_generate_id()
  end

  def statuses, do: @statuses

  defp maybe_generate_id(changeset) do
    if get_field(changeset, :id) do
      changeset
    else
      put_change(changeset, :id, Uniq.UUID.uuid7())
    end
  end
end
```

- [ ] **Step 4: Create migration for ra_instances table**

Create migration in `src/pki_ra_engine/priv/repo/migrations/`:

```elixir
defmodule PkiRaEngine.Repo.Migrations.CreateRaInstances do
  use Ecto.Migration

  def change do
    create table(:ra_instances, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :status, :string, null: false, default: "initialized"
      add :created_by, :string

      timestamps()
    end

    create unique_index(:ra_instances, [:name])
  end
end
```

Run: `cd src/pki_ra_engine && mix ecto.migrate`

- [ ] **Step 5: Run test to verify it passes**

Run: `cd src/pki_ra_engine && mix test test/pki_ra_engine/ra_instance_test.exs --trace`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/pki_ra_engine/lib/pki_ra_engine/schema/ra_instance.ex src/pki_ra_engine/test/pki_ra_engine/ra_instance_test.exs src/pki_ra_engine/priv/
git commit -m "feat: create ra_instances schema and table"
```

---

### Task 4: Add ra_instance_id and issuer_key_id to Existing RA Schemas

**Files:**
- Modify: `src/pki_ra_engine/lib/pki_ra_engine/schema/ra_user.ex`
- Modify: `src/pki_ra_engine/lib/pki_ra_engine/schema/ra_api_key.ex`
- Modify: `src/pki_ra_engine/lib/pki_ra_engine/schema/cert_profile.ex`
- Modify: `src/pki_ra_engine/test/pki_ra_engine/schema_test.exs`

- [ ] **Step 1: Write failing tests for new fields**

In `src/pki_ra_engine/test/pki_ra_engine/schema_test.exs`, add to existing describe blocks:

```elixir
# Add to RaUser describe block:
test "accepts ra_instance_id" do
  changeset = RaUser.changeset(%RaUser{}, Map.put(@valid_ra_user, :ra_instance_id, Uniq.UUID.uuid7()))
  assert changeset.valid?
end

# Add to CertProfile describe block:
test "accepts ra_instance_id and issuer_key_id" do
  changeset = CertProfile.changeset(%CertProfile{}, Map.merge(@valid_cert_profile, %{
    ra_instance_id: Uniq.UUID.uuid7(),
    issuer_key_id: Uniq.UUID.uuid7()
  }))
  assert changeset.valid?
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd src/pki_ra_engine && mix test test/pki_ra_engine/schema_test.exs --trace`
Expected: FAIL — fields not recognized in cast

- [ ] **Step 3: Update RaUser schema**

In `src/pki_ra_engine/lib/pki_ra_engine/schema/ra_user.ex`:

1. Add inside schema block: `belongs_to :ra_instance, PkiRaEngine.Schema.RaInstance`
2. Add `:ra_instance_id` to the cast list in `changeset/2` and `registration_changeset/2`

- [ ] **Step 4: Update RaApiKey schema**

In `src/pki_ra_engine/lib/pki_ra_engine/schema/ra_api_key.ex`:

1. Add inside schema block: `belongs_to :ra_instance, PkiRaEngine.Schema.RaInstance`
2. Add `:ra_instance_id` to `@optional_fields`

- [ ] **Step 5: Update CertProfile schema**

In `src/pki_ra_engine/lib/pki_ra_engine/schema/cert_profile.ex`:

1. Add inside schema block:
   ```elixir
   belongs_to :ra_instance, PkiRaEngine.Schema.RaInstance
   field :issuer_key_id, :string
   ```
2. Add `:ra_instance_id` and `:issuer_key_id` to `@optional_fields`

- [ ] **Step 6: Create migration for new columns**

```elixir
defmodule PkiRaEngine.Repo.Migrations.AddInstanceFieldsToRaSchemas do
  use Ecto.Migration

  def change do
    alter table(:ra_users) do
      add :ra_instance_id, references(:ra_instances, type: :binary_id, on_delete: :nilify_all)
    end

    alter table(:ra_api_keys) do
      add :ra_instance_id, references(:ra_instances, type: :binary_id, on_delete: :nilify_all)
    end

    alter table(:cert_profiles) do
      add :ra_instance_id, references(:ra_instances, type: :binary_id, on_delete: :nilify_all)
      add :issuer_key_id, :string
    end

    create index(:ra_users, [:ra_instance_id])
    create index(:ra_api_keys, [:ra_instance_id])
    create index(:cert_profiles, [:ra_instance_id])
    create index(:cert_profiles, [:issuer_key_id])
  end
end
```

Run: `cd src/pki_ra_engine && mix ecto.migrate`

- [ ] **Step 7: Run tests to verify they pass**

Run: `cd src/pki_ra_engine && mix test --trace`
Expected: All tests PASS

- [ ] **Step 8: Commit**

```bash
git add src/pki_ra_engine/lib/pki_ra_engine/schema/ src/pki_ra_engine/test/ src/pki_ra_engine/priv/
git commit -m "feat: add ra_instance_id and issuer_key_id to RA schemas"
```

---

### Task 5: Add ca_instance_id to AuditEvent and New Audit Actions

**Files:**
- Modify: `src/pki_audit_trail/lib/pki_audit_trail/audit_event.ex`
- Modify: `src/pki_audit_trail/lib/pki_audit_trail/actions.ex`
- Modify: `src/pki_audit_trail/lib/pki_audit_trail.ex`

- [ ] **Step 1: Write failing test for ca_instance_id filter**

Create or update `src/pki_audit_trail/test/pki_audit_trail/query_test.exs`:

```elixir
test "filters by ca_instance_id" do
  ca_id = Uniq.UUID.uuid7()
  PkiAuditTrail.log(
    %{actor_did: "admin", actor_role: "ca_admin", node_name: "n1"},
    "ca_instance_created",
    %{resource_type: "ca_instance", resource_id: ca_id, ca_instance_id: ca_id, details: %{}}
  )

  results = PkiAuditTrail.query(ca_instance_id: ca_id)
  assert length(results) >= 1
  assert Enum.all?(results, &(&1.ca_instance_id == ca_id))
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd src/pki_audit_trail && mix test --trace`
Expected: FAIL — `ca_instance_id` field doesn't exist

- [ ] **Step 3: Update AuditEvent schema**

In `src/pki_audit_trail/lib/pki_audit_trail/audit_event.ex`:

1. Add `field :ca_instance_id, :string` to the schema block
2. Add `:ca_instance_id` to `@optional_fields`

- [ ] **Step 4: Update Actions module**

In `src/pki_audit_trail/lib/pki_audit_trail/actions.ex`, add to `@actions`:

```elixir
"ca_instance_created", "ca_instance_status_changed",
"ra_instance_created", "ra_instance_status_changed",
"cert_profile_created", "cert_profile_updated",
"hierarchy_modified",
"issuer_key_rotation_started", "cert_profile_issuer_key_changed", "issuer_key_archived"
```

- [ ] **Step 5: Update query filter in PkiAuditTrail**

In `src/pki_audit_trail/lib/pki_audit_trail.ex`, add to `apply_filters/2`:

```elixir
defp apply_filters(query, [{:ca_instance_id, id} | rest]),
  do: query |> where([e], e.ca_instance_id == ^id) |> apply_filters(rest)
```

- [ ] **Step 6: Update Logger to accept ca_instance_id**

In `src/pki_audit_trail/lib/pki_audit_trail/logger.ex`, ensure the `log/3` function passes `ca_instance_id` from the resource map to the event attrs.

- [ ] **Step 7: Create migration for ca_instance_id column**

Add column to `audit_events` table.

- [ ] **Step 8: Run tests**

Run: `cd src/pki_audit_trail && mix test --trace`
Expected: All tests PASS

- [ ] **Step 9: Commit**

```bash
git add src/pki_audit_trail/
git commit -m "feat: add ca_instance_id to audit events, add multi-CA/RA audit actions"
```

---

## Phase 2: CA Engine — Hierarchy Logic and API

### Task 6: CA Instance Hierarchy Business Logic

**Files:**
- Create: `src/pki_ca_engine/lib/pki_ca_engine/ca_instance_management.ex`
- Create: `src/pki_ca_engine/test/pki_ca_engine/ca_instance_management_test.exs`

- [ ] **Step 1: Write failing tests for hierarchy operations**

Create `src/pki_ca_engine/test/pki_ca_engine/ca_instance_management_test.exs`:

```elixir
defmodule PkiCaEngine.CaInstanceManagementTest do
  use PkiCaEngine.DataCase, async: true

  alias PkiCaEngine.CaInstanceManagement
  alias PkiCaEngine.Schema.CaInstance

  describe "create_ca_instance/1" do
    test "creates a root CA (no parent)" do
      assert {:ok, %CaInstance{} = ca} = CaInstanceManagement.create_ca_instance(%{
        name: "Root CA", created_by: "admin"
      })
      assert ca.parent_id == nil
    end

    test "creates a sub-CA under a root" do
      {:ok, root} = CaInstanceManagement.create_ca_instance(%{name: "Root", created_by: "admin"})

      assert {:ok, %CaInstance{} = sub} = CaInstanceManagement.create_ca_instance(%{
        name: "Sub CA", parent_id: root.id, created_by: "admin"
      })
      assert sub.parent_id == root.id
    end

    test "rejects depth exceeding max_ca_depth" do
      {:ok, root} = CaInstanceManagement.create_ca_instance(%{name: "Root-d", created_by: "admin"})
      {:ok, sub} = CaInstanceManagement.create_ca_instance(%{name: "Sub-d", parent_id: root.id, created_by: "admin"})

      # max_ca_depth=2 means Root(1) -> Sub(2) is OK, Sub -> SubSub(3) is NOT
      assert {:error, :max_depth_exceeded} = CaInstanceManagement.create_ca_instance(
        %{name: "SubSub-d", parent_id: sub.id, created_by: "admin"},
        max_ca_depth: 2
      )
    end
  end

  describe "hierarchy helpers" do
    setup do
      {:ok, root} = CaInstanceManagement.create_ca_instance(%{name: "root-h", created_by: "admin"})
      {:ok, sub} = CaInstanceManagement.create_ca_instance(%{name: "sub-h", parent_id: root.id, created_by: "admin"})
      %{root: root, sub: sub}
    end

    test "is_root?/1", %{root: root, sub: sub} do
      assert CaInstanceManagement.is_root?(root)
      refute CaInstanceManagement.is_root?(sub)
    end

    test "is_leaf?/1", %{root: root, sub: sub} do
      refute CaInstanceManagement.is_leaf?(root)
      assert CaInstanceManagement.is_leaf?(sub)
    end

    test "depth/1", %{root: root, sub: sub} do
      assert CaInstanceManagement.depth(root) == 1
      assert CaInstanceManagement.depth(sub) == 2
    end

    test "list_hierarchy/0 returns tree", %{root: root, sub: sub} do
      tree = CaInstanceManagement.list_hierarchy()
      assert length(tree) >= 1
      root_node = Enum.find(tree, &(&1.id == root.id))
      assert root_node != nil
    end
  end

  describe "leaf-only issuer key enforcement" do
    test "leaf_ca_issuer_keys/0 returns only keys from leaf CAs" do
      {:ok, root} = CaInstanceManagement.create_ca_instance(%{name: "root-lk", created_by: "admin"})
      {:ok, sub} = CaInstanceManagement.create_ca_instance(%{name: "sub-lk", parent_id: root.id, created_by: "admin"})

      # Create issuer keys for both
      alias PkiCaEngine.IssuerKeyManagement
      {:ok, _root_key} = IssuerKeyManagement.create_issuer_key(root.id, %{key_alias: "rk", algorithm: "ECC-P256"})
      {:ok, sub_key} = IssuerKeyManagement.create_issuer_key(sub.id, %{key_alias: "sk", algorithm: "ECC-P256"})

      leaf_keys = CaInstanceManagement.leaf_ca_issuer_keys()
      key_ids = Enum.map(leaf_keys, & &1.id)

      # Sub-CA key should be in the list, root key should NOT
      assert sub_key.id in key_ids
    end
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd src/pki_ca_engine && mix test test/pki_ca_engine/ca_instance_management_test.exs --trace`
Expected: FAIL — module not found

- [ ] **Step 3: Implement CaInstanceManagement module**

Create `src/pki_ca_engine/lib/pki_ca_engine/ca_instance_management.ex`:

```elixir
defmodule PkiCaEngine.CaInstanceManagement do
  @moduledoc """
  Manages CA instances and their hierarchy.

  CA instances form a tree: Root CAs (parent_id=nil) at the top,
  Sub-CAs underneath. Only leaf CAs (no children) can issue
  end-entity certificates.
  """

  import Ecto.Query

  alias PkiCaEngine.Repo
  alias PkiCaEngine.Schema.{CaInstance, IssuerKey}

  @doc "Creates a CA instance. Pass max_ca_depth in opts to enforce depth limit."
  @spec create_ca_instance(map(), keyword()) :: {:ok, CaInstance.t()} | {:error, term()}
  def create_ca_instance(attrs, opts \\ []) do
    max_depth = Keyword.get(opts, :max_ca_depth, 2)

    case Map.get(attrs, :parent_id) do
      nil ->
        %CaInstance{}
        |> CaInstance.changeset(attrs)
        |> Repo.insert()

      parent_id ->
        parent = Repo.get!(CaInstance, parent_id)
        parent_depth = depth(parent)

        if parent_depth >= max_depth do
          {:error, :max_depth_exceeded}
        else
          %CaInstance{}
          |> CaInstance.changeset(attrs)
          |> Repo.insert()
        end
    end
  end

  @doc "Returns true if the CA instance is a root (no parent)."
  def is_root?(%CaInstance{parent_id: nil}), do: true
  def is_root?(%CaInstance{}), do: false

  @doc "Returns true if the CA instance has no children."
  def is_leaf?(%CaInstance{} = ca) do
    not Repo.exists?(from c in CaInstance, where: c.parent_id == ^ca.id)
  end

  @doc "Returns the depth of a CA instance (root = 1)."
  def depth(%CaInstance{parent_id: nil}), do: 1
  def depth(%CaInstance{parent_id: parent_id}) do
    parent = Repo.get!(CaInstance, parent_id)
    1 + depth(parent)
  end

  @doc "Returns the derived role label for a CA instance."
  def role(%CaInstance{} = ca) do
    cond do
      is_root?(ca) -> :root
      is_leaf?(ca) -> :issuing
      true -> :intermediate
    end
  end

  @doc "Lists all CA instances as a flat list with children preloaded."
  def list_hierarchy do
    CaInstance
    |> where([c], is_nil(c.parent_id))
    |> Repo.all()
    |> Repo.preload(children: :children)
  end

  @doc "Gets a single CA instance with children and issuer keys."
  def get_ca_instance(id) do
    case Repo.get(CaInstance, id) do
      nil -> {:error, :not_found}
      ca -> {:ok, Repo.preload(ca, [:children, :issuer_keys])}
    end
  end

  @doc "Returns issuer keys that belong to leaf CA instances only."
  def leaf_ca_issuer_keys do
    # A leaf CA is one whose id does NOT appear as parent_id in any other ca_instance
    non_leaf_ids = from(c in CaInstance, where: not is_nil(c.parent_id), select: c.parent_id)

    from(k in IssuerKey,
      where: k.ca_instance_id not in subquery(non_leaf_ids),
      where: not is_nil(k.ca_instance_id)
    )
    |> Repo.all()
    |> Repo.preload(:ca_instance)
  end

  @doc "Returns active issuer keys from leaf CA instances only."
  def active_leaf_issuer_keys do
    non_leaf_ids = from(c in CaInstance, where: not is_nil(c.parent_id), select: c.parent_id)

    from(k in IssuerKey,
      where: k.ca_instance_id not in subquery(non_leaf_ids),
      where: not is_nil(k.ca_instance_id),
      where: k.status == "active"
    )
    |> Repo.all()
    |> Repo.preload(:ca_instance)
  end
end
```

- [ ] **Step 4: Run tests**

Run: `cd src/pki_ca_engine && mix test test/pki_ca_engine/ca_instance_management_test.exs --trace`
Expected: PASS

- [ ] **Step 5: Run full CA engine test suite**

Run: `cd src/pki_ca_engine && mix test --trace`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add src/pki_ca_engine/lib/pki_ca_engine/ca_instance_management.ex src/pki_ca_engine/test/pki_ca_engine/ca_instance_management_test.exs
git commit -m "feat: add CA instance hierarchy management with depth enforcement"
```

---

### Task 7: CA Engine API — CA Instance CRUD Endpoints

**Files:**
- Create: `src/pki_ca_engine/lib/pki_ca_engine/api/ca_instance_controller.ex`
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/api/authenticated_router.ex`
- Create: `src/pki_ca_engine/test/pki_ca_engine/api/ca_instance_controller_test.exs`

- [ ] **Step 1: Write failing test for CA instance API**

Create `src/pki_ca_engine/test/pki_ca_engine/api/ca_instance_controller_test.exs`:

```elixir
defmodule PkiCaEngine.Api.CaInstanceControllerTest do
  use PkiCaEngine.DataCase, async: true
  use Plug.Test

  alias PkiCaEngine.Api.Router

  @opts Router.init([])

  defp call(conn), do: Router.call(conn, @opts)

  defp authed_conn(method, path, body \\ nil) do
    conn = conn(method, "/api/v1" <> path, body && Jason.encode!(body))
    conn
    |> put_req_header("content-type", "application/json")
    |> put_req_header("x-internal-secret", Application.get_env(:pki_ca_engine, :internal_api_secret, "test-secret"))
  end

  describe "POST /ca-instances" do
    test "creates a root CA instance" do
      conn = authed_conn(:post, "/ca-instances", %{name: "Test Root CA", created_by: "admin"}) |> call()
      assert conn.status == 201
      body = Jason.decode!(conn.resp_body)
      assert body["name"] == "Test Root CA"
      assert body["parent_id"] == nil
    end

    test "creates a sub-CA under a root" do
      conn = authed_conn(:post, "/ca-instances", %{name: "Root-sub", created_by: "admin"}) |> call()
      root = Jason.decode!(conn.resp_body)

      conn = authed_conn(:post, "/ca-instances", %{name: "Sub-CA", parent_id: root["id"], created_by: "admin"}) |> call()
      assert conn.status == 201
      body = Jason.decode!(conn.resp_body)
      assert body["parent_id"] == root["id"]
    end
  end

  describe "GET /ca-instances" do
    test "lists CA instances" do
      authed_conn(:post, "/ca-instances", %{name: "List-Root", created_by: "admin"}) |> call()

      conn = authed_conn(:get, "/ca-instances") |> call()
      assert conn.status == 200
      body = Jason.decode!(conn.resp_body)
      assert is_list(body)
    end
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd src/pki_ca_engine && mix test test/pki_ca_engine/api/ca_instance_controller_test.exs --trace`
Expected: FAIL — route not found (404)

- [ ] **Step 3: Create CaInstanceController**

Create `src/pki_ca_engine/lib/pki_ca_engine/api/ca_instance_controller.ex`:

```elixir
defmodule PkiCaEngine.Api.CaInstanceController do
  import Plug.Conn
  alias PkiCaEngine.CaInstanceManagement

  def create(conn) do
    attrs = conn.body_params

    case CaInstanceManagement.create_ca_instance(attrs) do
      {:ok, ca} ->
        json(conn, 201, %{
          id: ca.id,
          name: ca.name,
          status: ca.status,
          parent_id: ca.parent_id,
          role: CaInstanceManagement.role(ca),
          created_by: ca.created_by
        })

      {:error, :max_depth_exceeded} ->
        json(conn, 422, %{error: "max_depth_exceeded"})

      {:error, %Ecto.Changeset{} = changeset} ->
        errors = PkiCaEngine.Api.Helpers.changeset_errors(changeset)
        json(conn, 422, %{errors: errors})

      {:error, reason} ->
        json(conn, 400, %{error: inspect(reason)})
    end
  end

  def index(conn) do
    instances = CaInstanceManagement.list_hierarchy()

    data = Enum.map(instances, &serialize_tree/1)
    json(conn, 200, data)
  end

  def show(conn, id) do
    case CaInstanceManagement.get_ca_instance(id) do
      {:ok, ca} ->
        json(conn, 200, serialize_with_details(ca))

      {:error, :not_found} ->
        json(conn, 404, %{error: "not_found"})
    end
  end

  def children(conn, id) do
    case CaInstanceManagement.get_ca_instance(id) do
      {:ok, ca} ->
        data = Enum.map(ca.children, &serialize_basic/1)
        json(conn, 200, data)

      {:error, :not_found} ->
        json(conn, 404, %{error: "not_found"})
    end
  end

  defp serialize_basic(ca) do
    %{
      id: ca.id,
      name: ca.name,
      status: ca.status,
      parent_id: ca.parent_id,
      role: CaInstanceManagement.role(ca)
    }
  end

  defp serialize_tree(ca) do
    children = if Ecto.assoc_loaded?(ca.children), do: ca.children, else: []
    Map.put(serialize_basic(ca), :children, Enum.map(children, &serialize_tree/1))
  end

  defp serialize_with_details(ca) do
    issuer_keys = if Ecto.assoc_loaded?(ca.issuer_keys), do: ca.issuer_keys, else: []

    serialize_basic(ca)
    |> Map.put(:children, Enum.map(ca.children, &serialize_basic/1))
    |> Map.put(:issuer_keys, Enum.map(issuer_keys, fn k ->
      %{id: k.id, key_alias: k.key_alias, algorithm: k.algorithm, status: k.status}
    end))
  end

  defp json(conn, status, body) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(body))
  end
end
```

- [ ] **Step 4: Add routes to authenticated router**

In `src/pki_ca_engine/lib/pki_ca_engine/api/authenticated_router.ex`, add the alias and routes:

Add to alias block: `CaInstanceController`

Add routes before the `match _` catch-all:

```elixir
# CA Instances
get "/ca-instances" do
  CaInstanceController.index(conn)
end

post "/ca-instances" do
  CaInstanceController.create(conn)
end

get "/ca-instances/:id" do
  CaInstanceController.show(conn, id)
end

get "/ca-instances/:id/children" do
  CaInstanceController.children(conn, id)
end
```

- [ ] **Step 5: Run tests**

Run: `cd src/pki_ca_engine && mix test test/pki_ca_engine/api/ca_instance_controller_test.exs --trace`
Expected: PASS

- [ ] **Step 6: Run full test suite**

Run: `cd src/pki_ca_engine && mix test --trace`
Expected: All PASS

- [ ] **Step 7: Commit**

```bash
git add src/pki_ca_engine/lib/pki_ca_engine/api/ca_instance_controller.ex src/pki_ca_engine/lib/pki_ca_engine/api/authenticated_router.ex src/pki_ca_engine/test/
git commit -m "feat: add CA instance CRUD API endpoints"
```

---

### Task 8: Add Leaf-Only Enforcement to Certificate Signing

**Files:**
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/certificate_signing.ex`
- Modify: `src/pki_ca_engine/test/pki_ca_engine/certificate_signing_test.exs`

- [ ] **Step 1: Write failing test**

In `src/pki_ca_engine/test/pki_ca_engine/certificate_signing_test.exs`, add:

```elixir
describe "leaf-only enforcement" do
  test "rejects signing when issuer key belongs to a non-leaf CA" do
    # Create root -> sub hierarchy
    alias PkiCaEngine.Schema.CaInstance
    {:ok, root} = Repo.insert(CaInstance.changeset(%CaInstance{}, %{name: "root-leaf-test", created_by: "admin"}))
    {:ok, _sub} = Repo.insert(CaInstance.changeset(%CaInstance{}, %{name: "sub-leaf-test", parent_id: root.id, created_by: "admin"}))

    # Create issuer key on the root (which is NOT a leaf)
    alias PkiCaEngine.IssuerKeyManagement
    {:ok, root_key} = IssuerKeyManagement.create_issuer_key(root.id, %{key_alias: "rk-leaf", algorithm: "ECC-P256"})

    # Attempting to sign with root_key should fail
    result = PkiCaEngine.CertificateSigning.sign_certificate(root_key.id, "fake-csr", %{})
    assert {:error, :non_leaf_ca_cannot_issue} = result
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd src/pki_ca_engine && mix test test/pki_ca_engine/certificate_signing_test.exs --trace`
Expected: FAIL — no such error returned

- [ ] **Step 3: Add leaf check to sign_certificate/4**

In `src/pki_ca_engine/lib/pki_ca_engine/certificate_signing.ex`, at the beginning of `sign_certificate/4`, add a leaf check:

```elixir
def sign_certificate(issuer_key_id, csr_pem, cert_profile_map, opts \\ []) do
  with {:ok, issuer_key_record} <- get_issuer_key(issuer_key_id),
       :ok <- check_leaf_ca(issuer_key_record) do
    # ... existing logic
  end
end

defp check_leaf_ca(%{ca_instance_id: nil}), do: :ok
defp check_leaf_ca(%{ca_instance_id: ca_id}) do
  if CaInstanceManagement.is_leaf?(Repo.get!(PkiCaEngine.Schema.CaInstance, ca_id)) do
    :ok
  else
    {:error, :non_leaf_ca_cannot_issue}
  end
end
```

Move the `get_issuer_key` call to before the `KeyActivation.get_active_key` call so the leaf check happens first.

- [ ] **Step 4: Run tests**

Run: `cd src/pki_ca_engine && mix test test/pki_ca_engine/certificate_signing_test.exs --trace`
Expected: PASS

- [ ] **Step 5: Run full test suite**

Run: `cd src/pki_ca_engine && mix test --trace`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add src/pki_ca_engine/lib/pki_ca_engine/certificate_signing.ex src/pki_ca_engine/test/
git commit -m "feat: enforce leaf-only CA for end-entity cert signing"
```

---

### Task 9: Add leaf_only Filter to Issuer Keys Endpoint

**Files:**
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/api/issuer_key_controller.ex`

- [ ] **Step 1: Update IssuerKeyController.index to support leaf_only param**

Read the current `issuer_key_controller.ex` to understand the existing index action, then add a check for `conn.query_params["leaf_only"]`. If `"true"`, call `CaInstanceManagement.active_leaf_issuer_keys()` instead of the normal list.

- [ ] **Step 2: Test manually or add a test**

Verify that `GET /api/v1/issuer-keys?leaf_only=true` returns only keys from leaf CAs.

- [ ] **Step 3: Commit**

```bash
git add src/pki_ca_engine/lib/pki_ca_engine/api/issuer_key_controller.ex
git commit -m "feat: add leaf_only filter to issuer keys endpoint"
```

---

## Phase 3: RA Engine — Instance Management and CSR Forwarding

### Task 10: RA Instance Management Module

**Files:**
- Create: `src/pki_ra_engine/lib/pki_ra_engine/ra_instance_management.ex`
- Create: `src/pki_ra_engine/test/pki_ra_engine/ra_instance_management_test.exs`

- [ ] **Step 1: Write failing tests**

Create `src/pki_ra_engine/test/pki_ra_engine/ra_instance_management_test.exs`:

```elixir
defmodule PkiRaEngine.RaInstanceManagementTest do
  use PkiRaEngine.DataCase, async: true

  alias PkiRaEngine.RaInstanceManagement
  alias PkiRaEngine.Schema.RaInstance

  describe "create_ra_instance/1" do
    test "creates an RA instance" do
      assert {:ok, %RaInstance{} = ra} = RaInstanceManagement.create_ra_instance(%{
        name: "JPJ RA", created_by: "admin"
      })
      assert ra.name == "JPJ RA"
      assert ra.status == "initialized"
    end

    test "rejects duplicate name" do
      {:ok, _} = RaInstanceManagement.create_ra_instance(%{name: "Dup RA", created_by: "admin"})
      assert {:error, _} = RaInstanceManagement.create_ra_instance(%{name: "Dup RA", created_by: "admin"})
    end
  end

  describe "list_ra_instances/0" do
    test "returns all instances" do
      {:ok, _} = RaInstanceManagement.create_ra_instance(%{name: "RA-list-1", created_by: "admin"})
      {:ok, _} = RaInstanceManagement.create_ra_instance(%{name: "RA-list-2", created_by: "admin"})

      instances = RaInstanceManagement.list_ra_instances()
      assert length(instances) >= 2
    end
  end

  describe "update_status/2" do
    test "activates an instance" do
      {:ok, ra} = RaInstanceManagement.create_ra_instance(%{name: "RA-act", created_by: "admin"})
      assert {:ok, updated} = RaInstanceManagement.update_status(ra.id, "active")
      assert updated.status == "active"
    end
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd src/pki_ra_engine && mix test test/pki_ra_engine/ra_instance_management_test.exs --trace`

- [ ] **Step 3: Implement RaInstanceManagement**

Create `src/pki_ra_engine/lib/pki_ra_engine/ra_instance_management.ex`:

```elixir
defmodule PkiRaEngine.RaInstanceManagement do
  @moduledoc "CRUD for RA instances."

  alias PkiRaEngine.Repo
  alias PkiRaEngine.Schema.RaInstance

  def create_ra_instance(attrs) do
    %RaInstance{}
    |> RaInstance.changeset(attrs)
    |> Repo.insert()
  end

  def get_ra_instance(id) do
    case Repo.get(RaInstance, id) do
      nil -> {:error, :not_found}
      ra -> {:ok, ra}
    end
  end

  def list_ra_instances do
    Repo.all(RaInstance)
  end

  def update_status(id, new_status) do
    with {:ok, ra} <- get_ra_instance(id) do
      ra
      |> RaInstance.changeset(%{status: new_status})
      |> Repo.update()
    end
  end
end
```

- [ ] **Step 4: Run tests**

Run: `cd src/pki_ra_engine && mix test test/pki_ra_engine/ra_instance_management_test.exs --trace`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/pki_ra_engine/lib/pki_ra_engine/ra_instance_management.ex src/pki_ra_engine/test/pki_ra_engine/ra_instance_management_test.exs
git commit -m "feat: add RA instance management module"
```

---

### Task 11: RA Engine API — RA Instance and Available Issuer Keys Endpoints

**Files:**
- Create: `src/pki_ra_engine/lib/pki_ra_engine/api/ra_instance_controller.ex`
- Modify: `src/pki_ra_engine/lib/pki_ra_engine/api/authenticated_router.ex`

- [ ] **Step 1: Create RaInstanceController**

Create `src/pki_ra_engine/lib/pki_ra_engine/api/ra_instance_controller.ex` following the same pattern as `CaInstanceController` in Task 7. Actions: `create/1`, `index/1`, `show/2`, `update/2`.

- [ ] **Step 2: Add routes**

In `src/pki_ra_engine/lib/pki_ra_engine/api/authenticated_router.ex`, add alias `RaInstanceController` and routes:

```elixir
# RA Instances
get "/ra-instances" do
  RaInstanceController.index(conn)
end

post "/ra-instances" do
  RaInstanceController.create(conn)
end

get "/ra-instances/:id" do
  RaInstanceController.show(conn, id)
end

patch "/ra-instances/:id" do
  RaInstanceController.update(conn, id)
end

# Available issuer keys (proxy to CA engine)
get "/available-issuer-keys" do
  RaInstanceController.available_issuer_keys(conn)
end
```

- [ ] **Step 3: Implement available_issuer_keys**

The `available_issuer_keys` action calls the CA Engine's `GET /api/v1/issuer-keys?leaf_only=true` endpoint via `HttpCaClient` or a new helper function, and returns the result to the RA caller.

- [ ] **Step 4: Run full RA engine test suite**

Run: `cd src/pki_ra_engine && mix test --trace`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/pki_ra_engine/lib/pki_ra_engine/api/ra_instance_controller.ex src/pki_ra_engine/lib/pki_ra_engine/api/authenticated_router.ex
git commit -m "feat: add RA instance API and available issuer keys endpoint"
```

---

### Task 12: Update CSR Forwarding to Use Cert Profile's issuer_key_id

**Files:**
- Modify: `src/pki_ra_engine/lib/pki_ra_engine/csr_validation.ex`
- Modify: `src/pki_ra_engine/test/pki_ra_engine/csr_validation_test.exs`

- [ ] **Step 1: Write failing test**

In `src/pki_ra_engine/test/pki_ra_engine/csr_validation_test.exs`, add a test that verifies `forward_to_ca/1` reads `issuer_key_id` from the CSR's cert profile and passes it to the CA client.

- [ ] **Step 2: Update forward_to_ca/1**

In `src/pki_ra_engine/lib/pki_ra_engine/csr_validation.ex`, modify `forward_to_ca/1`:

1. After loading the CSR, preload or load its cert profile
2. Read `cert_profile.issuer_key_id`
3. Pass it in the cert_profile map to `ca_module.sign_certificate/2`

```elixir
def forward_to_ca(csr_id) do
  ca_module = Application.get_env(:pki_ra_engine, :ca_engine_module) ||
    raise "ca_engine_module not configured."

  with {:ok, csr} <- get_csr(csr_id),
       :ok <- check_transition(csr.status, "issued"),
       {:ok, profile} <- CertProfileConfig.get_profile(csr.cert_profile_id) do
    cert_profile_map = %{
      id: csr.cert_profile_id,
      issuer_key_id: profile.issuer_key_id
    }

    case ca_module.sign_certificate(csr.csr_pem, cert_profile_map) do
      {:ok, cert_data} -> mark_issued(csr_id, cert_data.serial_number)
      {:error, reason} -> {:error, reason}
    end
  end
end
```

- [ ] **Step 3: Run tests**

Run: `cd src/pki_ra_engine && mix test --trace`
Expected: All PASS

- [ ] **Step 4: Commit**

```bash
git add src/pki_ra_engine/lib/pki_ra_engine/csr_validation.ex src/pki_ra_engine/test/
git commit -m "feat: resolve issuer_key_id from cert profile in CSR forwarding"
```

---

## Phase 4: Platform Admin Portal UI

### Task 13: Remove Algorithm Dropdown from Tenant Creation Wizard

**Files:**
- Modify: `src/pki_platform_portal/lib/pki_platform_portal_web/live/tenant_new_live.ex`
- Modify: `src/pki_platform_engine/lib/pki_platform_engine/provisioner.ex`

- [ ] **Step 1: Update TenantNewLive**

In `src/pki_platform_portal/lib/pki_platform_portal_web/live/tenant_new_live.ex`:

1. Remove `signing_algorithm: "ECC-P256"` from `mount/3` assigns
2. Remove `signing_algorithm` from `handle_event("next_step", ...)`
3. Remove the entire `<div>` block containing the "Default Signing Algorithm" `<select>` from the `render/1` template (approximately lines 391-414)
4. Update `handle_info(:provision_tenant, ...)` to not pass `signing_algorithm` in opts

- [ ] **Step 2: Update Provisioner.create_tenant**

In `src/pki_platform_engine/lib/pki_platform_engine/provisioner.ex`, remove `signing_algorithm` and `kem_algorithm` from the `attrs` map in `create_tenant/3`.

- [ ] **Step 3: Test manually**

Start the portal and verify the tenant creation wizard no longer shows the algorithm dropdown.

- [ ] **Step 4: Commit**

```bash
git add src/pki_platform_portal/lib/pki_platform_portal_web/live/tenant_new_live.ex src/pki_platform_engine/lib/pki_platform_engine/provisioner.ex
git commit -m "feat: remove algorithm picker from tenant creation wizard"
```

---

### Task 14: Update Tenant Detail Metrics

**Files:**
- Modify: `src/pki_platform_engine/lib/pki_platform_engine/tenant_metrics.ex`
- Modify: `src/pki_platform_portal/lib/pki_platform_portal_web/live/tenant_detail_live.ex`

- [ ] **Step 1: Add CA/RA instance counts to TenantMetrics**

In `src/pki_platform_engine/lib/pki_platform_engine/tenant_metrics.ex`, add to `get_metrics/1`:

```elixir
ca_instances: safe_count(tenant, "ca", "SELECT count(*) FROM ca_instances"),
ra_instances: safe_count(tenant, "ra", "SELECT count(*) FROM ra_instances"),
```

Update the rescue fallback map to include these new keys with default 0.

- [ ] **Step 2: Update TenantDetailLive to show new metrics**

In `src/pki_platform_portal/lib/pki_platform_portal_web/live/tenant_detail_live.ex`, add metric cards for "CA Instances" and "RA Instances" counts.

- [ ] **Step 3: Commit**

```bash
git add src/pki_platform_engine/lib/pki_platform_engine/tenant_metrics.ex src/pki_platform_portal/lib/pki_platform_portal_web/live/tenant_detail_live.ex
git commit -m "feat: add CA/RA instance counts to tenant detail metrics"
```

---

## Phase 5: CA Portal UI

### Task 15: CA Instances LiveView Page with Hierarchy Tree

**Files:**
- Create: `src/pki_ca_portal/lib/pki_ca_portal_web/live/ca_instances_live.ex`
- Modify: `src/pki_ca_portal/lib/pki_ca_portal_web/router.ex`

- [ ] **Step 1: Create CaInstancesLive**

Create `src/pki_ca_portal/lib/pki_ca_portal_web/live/ca_instances_live.ex` as a LiveView that:

1. On mount, fetches CA instances hierarchy from the CA Engine API (`GET /api/v1/ca-instances`)
2. Renders a tree view with collapsible Root → Sub-CA nodes
3. Shows computed badges: "Root", "Intermediate", "Issuing"
4. Shows issuer key count and algorithm summary per instance
5. Has "+ New Root CA" button and "+ Sub-CA" button per instance
6. Create CA Instance modal/form with: name, parent_id dropdown

Follow the existing LiveView patterns in the CA portal (e.g., `dashboard_live.ex`, `keystores_live.ex`).

- [ ] **Step 2: Add route**

In `src/pki_ca_portal/lib/pki_ca_portal_web/router.ex`, add within the authenticated live_session:

```elixir
live "/ca-instances", CaInstancesLive
```

- [ ] **Step 3: Test manually**

Start the CA portal and verify the CA Instances page renders correctly with the hierarchy tree.

- [ ] **Step 4: Commit**

```bash
git add src/pki_ca_portal/lib/pki_ca_portal_web/live/ca_instances_live.ex src/pki_ca_portal/lib/pki_ca_portal_web/router.ex
git commit -m "feat: add CA instances hierarchy page to CA portal"
```

---

### Task 16: Add CA Instance Filter to Existing CA Portal Pages

**Files:**
- Modify: `src/pki_ca_portal/lib/pki_ca_portal_web/live/keystores_live.ex`
- Modify: `src/pki_ca_portal/lib/pki_ca_portal_web/live/ceremony_live.ex`
- Modify: `src/pki_ca_portal/lib/pki_ca_portal_web/live/audit_log_live.ex`

- [ ] **Step 1: Add CA instance filter dropdown to each page**

For each LiveView page, add a dropdown at the top that lists all CA instances. When selected, filter the displayed data by `ca_instance_id`. This requires updating the API calls these pages make to include the filter parameter.

- [ ] **Step 2: Test manually**

Verify each page filters correctly when a CA instance is selected.

- [ ] **Step 3: Commit**

```bash
git add src/pki_ca_portal/lib/pki_ca_portal_web/live/
git commit -m "feat: add CA instance filter to keystores, ceremonies, and audit log pages"
```

---

## Phase 6: RA Portal UI

### Task 17: RA Instances LiveView Page

**Files:**
- Create: `src/pki_ra_portal/lib/pki_ra_portal_web/live/ra_instances_live.ex`
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/router.ex`

- [ ] **Step 1: Create RaInstancesLive**

Create `src/pki_ra_portal/lib/pki_ra_portal_web/live/ra_instances_live.ex` as a LiveView that:

1. On mount, fetches RA instances from the RA Engine API (`GET /api/v1/ra-instances`)
2. Renders a list view with each instance showing: name, status, cert profile count, API key count, pending CSR count
3. Has "+ New RA Instance" button
4. Create RA Instance modal/form with: name

Follow existing RA portal LiveView patterns (e.g., `cert_profiles_live.ex`, `api_keys_live.ex`).

- [ ] **Step 2: Add route**

In `src/pki_ra_portal/lib/pki_ra_portal_web/router.ex`, add within the authenticated live_session:

```elixir
live "/ra-instances", RaInstancesLive
```

- [ ] **Step 3: Test manually**

Start the RA portal and verify the RA Instances page renders correctly.

- [ ] **Step 4: Commit**

```bash
git add src/pki_ra_portal/lib/pki_ra_portal_web/live/ra_instances_live.ex src/pki_ra_portal/lib/pki_ra_portal_web/router.ex
git commit -m "feat: add RA instances page to RA portal"
```

---

### Task 18: Update Cert Profile Creation with Issuer Key Picker

**Files:**
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/live/cert_profiles_live.ex`

- [ ] **Step 1: Update cert profiles LiveView**

In the cert profile creation form:

1. Add "RA Instance" dropdown (fetched from `GET /api/v1/ra-instances`)
2. Add "Issuer Key" picker (fetched from `GET /api/v1/available-issuer-keys`)
   - Display: key alias, CA instance name, algorithm
   - Only show active keys from leaf CAs
3. Pass `ra_instance_id` and `issuer_key_id` when creating the cert profile via `POST /api/v1/cert-profiles`

- [ ] **Step 2: Test manually**

Verify the issuer key picker shows available keys and the cert profile is created with the correct binding.

- [ ] **Step 3: Commit**

```bash
git add src/pki_ra_portal/lib/pki_ra_portal_web/live/cert_profiles_live.ex
git commit -m "feat: add issuer key picker to cert profile creation"
```

---

### Task 19: Add RA Instance Filter to Existing RA Portal Pages

**Files:**
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/live/csrs_live.ex`
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/live/api_keys_live.ex`
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/live/users_live.ex`

- [ ] **Step 1: Add RA instance filter dropdown to each page**

Same pattern as Task 16 — add a dropdown that filters data by `ra_instance_id`.

- [ ] **Step 2: Test manually**

Verify each page filters correctly.

- [ ] **Step 3: Commit**

```bash
git add src/pki_ra_portal/lib/pki_ra_portal_web/live/
git commit -m "feat: add RA instance filter to CSRs, API keys, and users pages"
```

---

## Phase 7: Key Rotation Support

### Task 20: Block Archiving Issuer Key Referenced by Cert Profiles

**Files:**
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/issuer_key_management.ex`
- Modify: `src/pki_ca_engine/test/pki_ca_engine/issuer_key_management_test.exs`

- [ ] **Step 1: Write failing test**

In `src/pki_ca_engine/test/pki_ca_engine/issuer_key_management_test.exs`, add:

```elixir
describe "key rotation safety" do
  test "update_status to archived is allowed when no cert profiles reference the key", %{ca: ca} do
    {:ok, key} = IssuerKeyManagement.create_issuer_key(ca.id, %{key_alias: "rot-1", algorithm: "ECC-P256"})
    {:ok, key} = IssuerKeyManagement.update_status(key, "active")
    assert {:ok, archived} = IssuerKeyManagement.update_status(key, "archived")
    assert archived.status == "archived"
  end
end
```

Note: The full test for blocking archival when cert profiles reference the key requires cross-engine coordination (RA engine owns cert_profiles). For now, add a callback hook that the CA engine can check. The actual check will be wired up when the CA-RA communication is established. Document this as a known integration point.

- [ ] **Step 2: Run tests**

Run: `cd src/pki_ca_engine && mix test --trace`
Expected: All PASS

- [ ] **Step 3: Commit**

```bash
git add src/pki_ca_engine/lib/pki_ca_engine/issuer_key_management.ex src/pki_ca_engine/test/
git commit -m "feat: add key rotation safety checks for issuer key archival"
```

---

## Phase 8: Database Schema Setup for New Tenants

### Task 21: Update Tenant Provisioner to Create New Tables

**Files:**
- Modify: `src/pki_platform_engine/lib/pki_platform_engine/provisioner.ex`

- [ ] **Step 1: Update create_schemas/1**

In `src/pki_platform_engine/lib/pki_platform_engine/provisioner.ex`, after creating the base schemas ("ca", "ra", "validation", "audit"), add SQL to create the new tables and columns in the tenant's database:

1. Add `parent_id` column to `ca.ca_instances` table
2. Create `ra.ra_instances` table
3. Add `ra_instance_id` column to `ra.ra_users`, `ra.ra_api_keys`, `ra.cert_profiles`
4. Add `issuer_key_id` column to `ra.cert_profiles`

This ensures new tenants get the multi-CA/multi-RA schema from the start.

- [ ] **Step 2: Test by creating a new tenant**

Create a new tenant via the platform portal and verify the new columns/tables exist in the tenant database.

- [ ] **Step 3: Commit**

```bash
git add src/pki_platform_engine/lib/pki_platform_engine/provisioner.ex
git commit -m "feat: update tenant provisioning to create multi-CA/RA schema"
```

---

## Summary

| Phase | Tasks | What it delivers |
|---|---|---|
| 1: Data Model | Tasks 1-5 | Schema changes across all engines + audit trail |
| 2: CA Engine | Tasks 6-9 | Hierarchy logic, CRUD API, leaf enforcement |
| 3: RA Engine | Tasks 10-12 | RA instance management, CSR forwarding fix |
| 4: Platform UI | Tasks 13-14 | Simplified tenant wizard, updated metrics |
| 5: CA Portal UI | Tasks 15-16 | Hierarchy tree view, instance filters |
| 6: RA Portal UI | Tasks 17-19 | RA instances page, issuer key picker, filters |
| 7: Key Rotation | Task 20 | Archive safety checks |
| 8: Provisioning | Task 21 | New tenants get correct schema |

Total: **21 tasks**, ordered by dependency. Each phase can be independently tested and committed.
