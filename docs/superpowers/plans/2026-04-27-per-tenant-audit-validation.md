# Per-Tenant Audit Trail & Validation Schema Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `pki_audit_trail`'s hash-chained `audit_events` table work per-tenant in schema-mode deployments, and provision per-tenant validation schemas.

**Architecture:** The schema-mode VPS runs one BEAM node where each tenant has PostgreSQL schemas `t_<hex>_{ca,ra,audit}`. The provisioner already creates the `audit` schema but never populates it. This plan: (1) creates `t_<hex>_audit.audit_events` at provisioning time via a new SQL file, (2) adds a per-tenant ETS hash-chain store so `PkiAuditTrail.log/4` can write hash-chained events without a singleton, (3) routes events through this path from `PlatformAudit.log/2` for schema-mode tenants only, and (4) provisions per-tenant validation schemas. BEAM-mode tenants (no Postgres schemas) are unaffected — they continue using AuditBridge → Mnesia + PlatformAudit.

**Tech Stack:** Elixir/Phoenix, Ecto, PostgreSQL, ETS (for per-tenant hash-chain cache), raw SQL provisioning (existing Provisioner pattern).

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `src/pki_platform_engine/priv/tenant_audit_schema.sql` | Create | DDL for `audit_events` table in per-tenant audit schema |
| `src/pki_platform_engine/priv/tenant_validation_schema.sql` | Create | DDL for `certificate_status`, `crl_metadata`, `signing_key_config` tables |
| `src/pki_platform_engine/lib/pki_platform_engine/tenant_prefix.ex` | Modify | Add `validation_prefix/1`, update regex and `all_prefixes/1` |
| `src/pki_platform_engine/lib/pki_platform_engine/provisioner.ex` | Modify | Add audit/validation SQL runs in `run_tenant_migrations/1`; expose public helpers |
| `src/pki_audit_trail/lib/pki_audit_trail/hash_chain_store.ex` | Create | ETS-backed GenServer; maps `tenant_id → prev_hash` |
| `src/pki_audit_trail/lib/pki_audit_trail/application.ex` | Modify | Start `HashChainStore` in supervision tree |
| `src/pki_audit_trail/lib/pki_audit_trail/actions.ex` | Modify | Expand action list to cover all `pki_tenant_web` call sites |
| `src/pki_audit_trail/lib/pki_audit_trail.ex` | Modify | Add `log/4` per-tenant function |
| `src/pki_platform_engine/lib/pki_platform_engine/platform_audit.ex` | Modify | After platform write, also write hash-chained per-tenant audit for schema-mode tenants |
| `src/pki_platform_engine/lib/mix/tasks/pki.migrate_existing_tenants.ex` | Create | Idempotent mix task to patch existing schema-mode tenants on VPS |

---

### Task 1: `tenant_audit_schema.sql` and provisioner wiring

**Files:**
- Create: `src/pki_platform_engine/priv/tenant_audit_schema.sql`
- Modify: `src/pki_platform_engine/lib/pki_platform_engine/provisioner.ex`
- Test: `src/pki_platform_engine/test/pki_platform_engine/provisioner_audit_schema_test.exs`

- [ ] **Step 1: Write the failing test**

```elixir
# src/pki_platform_engine/test/pki_platform_engine/provisioner_audit_schema_test.exs
defmodule PkiPlatformEngine.ProvisionerAuditSchemaTest do
  use PkiPlatformEngine.DataCase, async: false

  alias PkiPlatformEngine.{Provisioner, TenantPrefix, PlatformRepo}
  alias PkiPlatformEngine.Tenant

  test "schema-mode provisioning creates audit_events table in audit prefix" do
    slug = "test-audit-#{System.unique_integer([:positive])}"
    {:ok, tenant} = Provisioner.create_tenant("Test Audit Tenant", slug,
      schema_mode: "schema")

    on_exit(fn -> Provisioner.delete_tenant(tenant.id) end)

    prefix = TenantPrefix.audit_prefix(tenant.id)
    {:ok, result} = Ecto.Adapters.SQL.query(
      PlatformRepo,
      "SELECT COUNT(*) FROM information_schema.tables
       WHERE table_schema = $1 AND table_name = 'audit_events'",
      [prefix]
    )
    assert [[1]] = result.rows
  end

  test "provisioning creates validation tables" do
    slug = "test-val-#{System.unique_integer([:positive])}"
    {:ok, tenant} = Provisioner.create_tenant("Test Val Tenant", slug,
      schema_mode: "schema")

    on_exit(fn -> Provisioner.delete_tenant(tenant.id) end)

    prefix = TenantPrefix.validation_prefix(tenant.id)
    {:ok, result} = Ecto.Adapters.SQL.query(
      PlatformRepo,
      "SELECT table_name FROM information_schema.tables
       WHERE table_schema = $1 ORDER BY table_name",
      [prefix]
    )
    table_names = Enum.map(result.rows, &List.first/1)
    assert "certificate_status" in table_names
    assert "crl_metadata" in table_names
    assert "signing_key_config" in table_names
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd src/pki_platform_engine && mix test test/pki_platform_engine/provisioner_audit_schema_test.exs -v
```

Expected: FAIL — `validation_prefix/1` undefined, and audit_events table not found.

- [ ] **Step 3: Create `tenant_audit_schema.sql`**

The `rewrite_schema_prefix/3` function in Provisioner rewrites `audit.` → `"t_<hex>_audit".` and strips the `CREATE SCHEMA` line. Use `audit` as the source schema name.

```sql
-- src/pki_platform_engine/priv/tenant_audit_schema.sql
-- Per-tenant hash-chained audit event log.
-- Schema prefix "audit." is rewritten to "t_<hex>_audit." by Provisioner.
CREATE SCHEMA IF NOT EXISTS audit;
CREATE TABLE IF NOT EXISTS audit.audit_events (
    id bigint NOT NULL,
    event_id uuid NOT NULL,
    "timestamp" timestamp(6) without time zone NOT NULL,
    node_name character varying(255) NOT NULL,
    actor_did character varying(255) NOT NULL,
    actor_role character varying(255) NOT NULL,
    action character varying(255) NOT NULL,
    resource_type character varying(255) NOT NULL,
    resource_id character varying(255) NOT NULL,
    details jsonb DEFAULT '{}'::jsonb,
    prev_hash character varying(64) NOT NULL,
    event_hash character varying(64) NOT NULL,
    ca_instance_id character varying(255)
);
CREATE SEQUENCE IF NOT EXISTS audit.audit_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
ALTER SEQUENCE audit.audit_events_id_seq OWNED BY audit.audit_events.id;
ALTER TABLE ONLY audit.audit_events ALTER COLUMN id SET DEFAULT nextval('audit.audit_events_id_seq'::regclass);
ALTER TABLE ONLY audit.audit_events
    ADD CONSTRAINT audit_events_pkey PRIMARY KEY (id);
CREATE UNIQUE INDEX IF NOT EXISTS audit_events_event_id_index ON audit.audit_events (event_id);
CREATE INDEX IF NOT EXISTS audit_events_action_index ON audit.audit_events (action);
CREATE INDEX IF NOT EXISTS audit_events_actor_did_index ON audit.audit_events (actor_did);
CREATE INDEX IF NOT EXISTS audit_events_resource_type_resource_id_index ON audit.audit_events (resource_type, resource_id);
CREATE INDEX IF NOT EXISTS audit_events_timestamp_index ON audit.audit_events ("timestamp");
CREATE INDEX IF NOT EXISTS audit_events_ca_instance_id_index ON audit.audit_events (ca_instance_id);
```

- [ ] **Step 4: Add `validation_prefix/1` to `TenantPrefix`**

Edit `src/pki_platform_engine/lib/pki_platform_engine/tenant_prefix.ex`:

```elixir
# Change the regex from:
@prefix_pattern ~r/\At_[0-9a-f]{32}_(ca|ra|audit)\z/
# To:
@prefix_pattern ~r/\At_[0-9a-f]{32}_(ca|ra|audit|validation)\z/

# Add after audit_prefix/1:
@doc "Validation schema prefix for a tenant."
def validation_prefix(tenant_id), do: "t_#{uuid_hex(tenant_id)}_validation"

# Update all_prefixes/1 to include validation_prefix:
def all_prefixes(tenant_id) do
  %{
    ca_prefix: ca_prefix(tenant_id),
    ra_prefix: ra_prefix(tenant_id),
    audit_prefix: audit_prefix(tenant_id),
    validation_prefix: validation_prefix(tenant_id)
  }
end
```

Since `create_tenant_schemas/1` and `drop_tenant_schemas/1` both iterate `all_prefixes(tenant_id)`, they will automatically create/drop the validation schema with no further changes.

- [ ] **Step 5: Create `tenant_validation_schema.sql`**

```sql
-- src/pki_platform_engine/priv/tenant_validation_schema.sql
-- Per-tenant validation tables: certificate status, CRL metadata, signing key config.
-- Schema prefix "validation." is rewritten to "t_<hex>_validation." by Provisioner.
CREATE SCHEMA IF NOT EXISTS validation;

CREATE TABLE IF NOT EXISTS validation.certificate_status (
    id bigint NOT NULL,
    serial_number character varying(255) NOT NULL,
    issuer_key_id bigint NOT NULL,
    subject_dn character varying(255) NOT NULL,
    status character varying(255) DEFAULT 'active'::character varying NOT NULL,
    not_before timestamp(6) without time zone NOT NULL,
    not_after timestamp(6) without time zone NOT NULL,
    revoked_at timestamp(6) without time zone,
    revocation_reason character varying(255),
    issuer_name_hash bytea,
    inserted_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL
);
CREATE SEQUENCE IF NOT EXISTS validation.certificate_status_id_seq
    START WITH 1 INCREMENT BY 1 NO MINVALUE NO MAXVALUE CACHE 1;
ALTER SEQUENCE validation.certificate_status_id_seq OWNED BY validation.certificate_status.id;
ALTER TABLE ONLY validation.certificate_status ALTER COLUMN id SET DEFAULT nextval('validation.certificate_status_id_seq'::regclass);
ALTER TABLE ONLY validation.certificate_status
    ADD CONSTRAINT certificate_status_pkey PRIMARY KEY (id);
CREATE UNIQUE INDEX IF NOT EXISTS certificate_status_serial_number_index ON validation.certificate_status (serial_number);
CREATE INDEX IF NOT EXISTS certificate_status_status_index ON validation.certificate_status (status);
CREATE INDEX IF NOT EXISTS certificate_status_issuer_key_id_index ON validation.certificate_status (issuer_key_id);
CREATE INDEX IF NOT EXISTS certificate_status_issuer_key_id_serial_number_index ON validation.certificate_status (issuer_key_id, serial_number);
CREATE INDEX IF NOT EXISTS certificate_status_status_revoked_at_index ON validation.certificate_status (status, revoked_at);

CREATE TABLE IF NOT EXISTS validation.crl_metadata (
    id uuid NOT NULL,
    issuer_key_id uuid NOT NULL,
    crl_number bigint DEFAULT 1 NOT NULL,
    last_generated_at timestamp(6) without time zone,
    last_der_bytes bytea,
    last_der_size integer DEFAULT 0,
    generation_count integer DEFAULT 0 NOT NULL,
    inserted_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL
);
ALTER TABLE ONLY validation.crl_metadata
    ADD CONSTRAINT crl_metadata_pkey PRIMARY KEY (id);
CREATE UNIQUE INDEX IF NOT EXISTS crl_metadata_issuer_key_id_index ON validation.crl_metadata (issuer_key_id);

CREATE TABLE IF NOT EXISTS validation.signing_key_config (
    id uuid NOT NULL,
    issuer_key_id uuid NOT NULL,
    algorithm character varying(255) NOT NULL,
    certificate_pem text NOT NULL,
    encrypted_private_key bytea NOT NULL,
    not_before timestamp(6) without time zone NOT NULL,
    not_after timestamp(6) without time zone NOT NULL,
    status character varying(255) DEFAULT 'active'::character varying NOT NULL,
    inserted_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL
);
ALTER TABLE ONLY validation.signing_key_config
    ADD CONSTRAINT signing_key_config_pkey PRIMARY KEY (id);
CREATE INDEX IF NOT EXISTS signing_key_config_issuer_key_id_index ON validation.signing_key_config (issuer_key_id);
CREATE UNIQUE INDEX IF NOT EXISTS signing_key_config_one_active_per_issuer
    ON validation.signing_key_config (issuer_key_id) WHERE (status = 'active');
```

- [ ] **Step 6: Wire audit and validation SQL in `run_tenant_migrations/1`**

Edit `src/pki_platform_engine/lib/pki_platform_engine/provisioner.ex`, replace the `run_tenant_migrations/1` body (lines 193–212):

```elixir
defp run_tenant_migrations(prefixes) do
  try do
    Logger.info("tenant_migration_start prefix=#{prefixes.ca_prefix} engine=ca")
    apply_tenant_schema_sql("tenant_ca_schema.sql", "ca", prefixes.ca_prefix)
    Logger.info("tenant_migration_done prefix=#{prefixes.ca_prefix} engine=ca")

    Logger.info("tenant_migration_start prefix=#{prefixes.ra_prefix} engine=ra")
    apply_tenant_schema_sql("tenant_ra_schema.sql", "ra", prefixes.ra_prefix)
    Logger.info("tenant_migration_done prefix=#{prefixes.ra_prefix} engine=ra")

    Logger.info("tenant_migration_start prefix=#{prefixes.audit_prefix} engine=audit")
    apply_tenant_schema_sql("tenant_audit_schema.sql", "audit", prefixes.audit_prefix)
    Logger.info("tenant_migration_done prefix=#{prefixes.audit_prefix} engine=audit")

    Logger.info("tenant_migration_start prefix=#{prefixes.validation_prefix} engine=validation")
    apply_tenant_schema_sql("tenant_validation_schema.sql", "validation", prefixes.validation_prefix)
    Logger.info("tenant_migration_done prefix=#{prefixes.validation_prefix} engine=validation")

    :ok
  rescue
    e ->
      Logger.error("tenant_migration_failed error=#{Exception.message(e)}")
      {:error, {:migration_failed, Exception.message(e)}}
  end
end
```

Also add two public helpers after `run_tenant_migrations/1` (above the private section) for use by the mix task:

```elixir
@doc "Public: run a single schema SQL file against a target prefix. Idempotent (uses IF NOT EXISTS)."
def apply_schema_sql(filename, source_schema, target_prefix) do
  apply_tenant_schema_sql(filename, source_schema, target_prefix)
end

@doc "Public: create a schema if it does not already exist."
def ensure_schema_exists(prefix) do
  safe = TenantPrefix.validate_prefix!(prefix)
  with_platform_conn(fn conn ->
    case Postgrex.query(conn, "CREATE SCHEMA IF NOT EXISTS \"#{safe}\"", []) do
      {:ok, _} -> :ok
      {:error, reason} -> raise "ensure_schema_exists failed for #{prefix}: #{inspect(reason)}"
    end
  end)
end
```

- [ ] **Step 7: Run tests to verify they pass**

```bash
cd src/pki_platform_engine && mix test test/pki_platform_engine/provisioner_audit_schema_test.exs -v
```

Expected: 2 tests, 0 failures.

- [ ] **Step 8: Commit**

```bash
git add src/pki_platform_engine/priv/tenant_audit_schema.sql \
        src/pki_platform_engine/priv/tenant_validation_schema.sql \
        src/pki_platform_engine/lib/pki_platform_engine/tenant_prefix.ex \
        src/pki_platform_engine/lib/pki_platform_engine/provisioner.ex \
        src/pki_platform_engine/test/pki_platform_engine/provisioner_audit_schema_test.exs
git commit -m "feat: provision per-tenant audit and validation schemas"
```

---

### Task 2: `PkiAuditTrail.HashChainStore` (per-tenant ETS hash chain)

**Files:**
- Create: `src/pki_audit_trail/lib/pki_audit_trail/hash_chain_store.ex`
- Modify: `src/pki_audit_trail/lib/pki_audit_trail/application.ex`
- Test: `src/pki_audit_trail/test/pki_audit_trail/hash_chain_store_test.exs`

- [ ] **Step 1: Write the failing test**

```elixir
# src/pki_audit_trail/test/pki_audit_trail/hash_chain_store_test.exs
defmodule PkiAuditTrail.HashChainStoreTest do
  use ExUnit.Case, async: false

  alias PkiAuditTrail.HashChainStore

  @genesis String.duplicate("0", 64)

  setup do
    # Start a fresh store for each test (stop any existing one)
    case GenServer.whereis(HashChainStore) do
      nil -> :ok
      pid -> GenServer.stop(pid)
    end
    {:ok, _} = HashChainStore.start_link([])
    :ok
  end

  test "returns genesis hash for tenant with no events" do
    tenant_id = Ecto.UUID.generate()
    assert HashChainStore.get_or_seed(tenant_id) == @genesis
  end

  test "caches in ETS after first call" do
    tenant_id = Ecto.UUID.generate()
    HashChainStore.get_or_seed(tenant_id)
    # Second call hits ETS, same result
    assert HashChainStore.get_or_seed(tenant_id) == @genesis
  end

  test "update stores new hash in ETS" do
    tenant_id = Ecto.UUID.generate()
    new_hash = String.duplicate("a", 64)
    HashChainStore.get_or_seed(tenant_id)
    :ok = HashChainStore.update(tenant_id, new_hash)
    assert HashChainStore.get_or_seed(tenant_id) == new_hash
  end

  test "different tenants have independent hashes" do
    t1 = Ecto.UUID.generate()
    t2 = Ecto.UUID.generate()
    HashChainStore.update(t1, String.duplicate("1", 64))
    HashChainStore.update(t2, String.duplicate("2", 64))
    assert HashChainStore.get_or_seed(t1) == String.duplicate("1", 64)
    assert HashChainStore.get_or_seed(t2) == String.duplicate("2", 64)
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd src/pki_audit_trail && mix test test/pki_audit_trail/hash_chain_store_test.exs -v
```

Expected: FAIL — `PkiAuditTrail.HashChainStore` undefined.

- [ ] **Step 3: Create `hash_chain_store.ex`**

```elixir
# src/pki_audit_trail/lib/pki_audit_trail/hash_chain_store.ex
defmodule PkiAuditTrail.HashChainStore do
  @moduledoc """
  ETS-backed store of per-tenant prev_hash values for the audit hash chain.

  On first access for a tenant, queries the DB for the last event_hash in that
  tenant's audit schema. On miss (no events yet) returns the genesis value.
  Updates are in-memory only; the authoritative value is always the DB.
  """
  use GenServer
  require Logger

  @table :pki_audit_hash_chain
  @genesis String.duplicate("0", 64)

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @doc "Returns the current prev_hash for tenant_id, seeding from DB on first call."
  def get_or_seed(tenant_id) when is_binary(tenant_id) do
    case :ets.lookup(@table, tenant_id) do
      [{_, hash}] -> hash
      [] ->
        hash = load_prev_hash(tenant_id)
        :ets.insert(@table, {tenant_id, hash})
        hash
    end
  end

  @doc "Updates the cached hash after a successful insert."
  def update(tenant_id, hash) when is_binary(tenant_id) and is_binary(hash) do
    :ets.insert(@table, {tenant_id, hash})
    :ok
  end

  @impl true
  def init(_opts) do
    :ets.new(@table, [:named_table, :public, :set, read_concurrency: true])
    {:ok, %{}}
  end

  defp load_prev_hash(tenant_id) do
    import Ecto.Query
    prefix = audit_prefix(tenant_id)

    query =
      from e in PkiAuditTrail.AuditEvent,
        order_by: [desc: e.id],
        limit: 1,
        select: e.event_hash

    PkiAuditTrail.Repo.one(query, prefix: prefix) || @genesis
  rescue
    _ -> @genesis
  end

  # Inlined prefix so pki_audit_trail does not depend on pki_platform_engine.
  defp audit_prefix(tenant_id) do
    hex = String.replace(tenant_id, "-", "")
    "t_#{hex}_audit"
  end
end
```

- [ ] **Step 4: Start `HashChainStore` in `PkiAuditTrail.Application`**

Read the current children list in `application.ex`. Add `PkiAuditTrail.HashChainStore` as the first child (before `Repo`), outside the `if Application.get_env(:pki_audit_trail, :start_application, true)` guard — it uses only ETS, no Postgres at startup:

```elixir
# In the children list, add unconditionally before the Repo child:
PkiAuditTrail.HashChainStore,
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd src/pki_audit_trail && mix test test/pki_audit_trail/hash_chain_store_test.exs -v
```

Expected: 4 tests, 0 failures.

- [ ] **Step 6: Commit**

```bash
git add src/pki_audit_trail/lib/pki_audit_trail/hash_chain_store.ex \
        src/pki_audit_trail/lib/pki_audit_trail/application.ex \
        src/pki_audit_trail/test/pki_audit_trail/hash_chain_store_test.exs
git commit -m "feat: PkiAuditTrail.HashChainStore — per-tenant ETS hash chain cache"
```

---

### Task 3: Expand Actions list + `PkiAuditTrail.log/4`

**Files:**
- Modify: `src/pki_audit_trail/lib/pki_audit_trail/actions.ex`
- Modify: `src/pki_audit_trail/lib/pki_audit_trail.ex`
- Test: `src/pki_audit_trail/test/pki_audit_trail/tenant_log_test.exs`

- [ ] **Step 1: Write the failing test**

```elixir
# src/pki_audit_trail/test/pki_audit_trail/tenant_log_test.exs
defmodule PkiAuditTrail.TenantLogTest do
  use PkiAuditTrail.DataCase, async: false

  @tenant_id "11111111-1111-1111-1111-111111111111"
  @prefix "t_11111111111111111111111111111111_audit"
  @genesis String.duplicate("0", 64)

  setup do
    # Create the audit_events table in the test DB under the test prefix.
    Ecto.Adapters.SQL.query!(
      PkiAuditTrail.Repo,
      """
      CREATE SCHEMA IF NOT EXISTS "#{@prefix}";
      CREATE TABLE IF NOT EXISTS "#{@prefix}".audit_events (
        id bigserial PRIMARY KEY,
        event_id uuid NOT NULL,
        "timestamp" timestamp(6) NOT NULL,
        node_name varchar(255) NOT NULL,
        actor_did varchar(255) NOT NULL,
        actor_role varchar(255) NOT NULL,
        action varchar(255) NOT NULL,
        resource_type varchar(255) NOT NULL,
        resource_id varchar(255) NOT NULL,
        details jsonb DEFAULT '{}',
        prev_hash varchar(64) NOT NULL,
        event_hash varchar(64) NOT NULL,
        ca_instance_id varchar(255)
      )
      """,
      []
    )

    on_exit(fn ->
      Ecto.Adapters.SQL.query!(
        PkiAuditTrail.Repo,
        "DROP SCHEMA IF EXISTS \"#{@prefix}\" CASCADE",
        []
      )
    end)

    :ok
  end

  test "log/4 writes an event to the tenant audit schema" do
    actor = %{actor_did: "user:alice", actor_role: "ca_admin"}
    resource = %{resource_type: "certificate", resource_id: "cert-1", details: %{}}

    assert {:ok, event} = PkiAuditTrail.log(@tenant_id, actor, "certificate_issued", resource)
    assert event.actor_did == "user:alice"
    assert event.action == "certificate_issued"
    assert event.prev_hash == @genesis
  end

  test "second event's prev_hash equals first event's event_hash" do
    actor = %{actor_did: "user:bob", actor_role: "ca_admin"}
    r1 = %{resource_type: "certificate", resource_id: "c1", details: %{}}
    r2 = %{resource_type: "certificate", resource_id: "c2", details: %{}}

    {:ok, e1} = PkiAuditTrail.log(@tenant_id, actor, "certificate_issued", r1)
    {:ok, e2} = PkiAuditTrail.log(@tenant_id, actor, "certificate_revoked", r2)

    assert e2.prev_hash == e1.event_hash
  end

  test "log/4 returns {:error, ...} when table is missing — does not raise" do
    bad_tenant_id = "22222222-2222-2222-2222-222222222222"
    actor = %{actor_did: "system", actor_role: "system"}
    resource = %{resource_type: "test", resource_id: "x", details: %{}}

    result = PkiAuditTrail.log(bad_tenant_id, actor, "certificate_issued", resource)
    assert {:error, _} = result
  end

  test "Actions.valid?/1 returns true for portal action strings" do
    portal_actions = ~w[
      keystore_configured activation_lease_granted csr_submitted_via_portal
      dcv_started dcv_passed certificate_revoked ca_instance_created
      issuer_key_unlocked issuer_key_retired api_key_created profile_updated
      password_changed ceremony_initiated ceremony_key_generated hsm_wizard_completed
    ]

    for action <- portal_actions do
      assert PkiAuditTrail.Actions.valid?(action), "Expected #{action} to be valid"
    end
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd src/pki_audit_trail && mix test test/pki_audit_trail/tenant_log_test.exs -v
```

Expected: FAIL — `PkiAuditTrail.log/4` undefined, several actions not valid.

- [ ] **Step 3: Expand `actions.ex`**

Replace the entire `@actions` list in `src/pki_audit_trail/lib/pki_audit_trail/actions.ex`:

```elixir
@actions [
  # Certificate lifecycle
  "certificate_issued", "certificate_revoked",
  # CSR
  "csr_submitted", "csr_verified", "csr_approved", "csr_rejected",
  "csr_submitted_via_portal", "csr_signed",
  # DCV
  "dcv_started", "dcv_passed",
  # Ceremony
  "ceremony_started", "ceremony_completed", "ceremony_initiated",
  "ceremony_cancelled", "ceremony_deleted",
  "ceremony_share_accepted", "ceremony_key_generated",
  "custodian_share_accepted",
  # Auditor witness
  "auditor_witnessed", "auditor_accepted_ceremony", "auditor_signed_transcript",
  # Key / Issuer key lifecycle
  "key_generated", "key_activated", "key_suspended",
  "key_activated_with_external_cert",
  "issuer_key_unlocked", "issuer_key_suspended", "issuer_key_reactivated",
  "issuer_key_retired", "issuer_key_archived",
  "issuer_key_rotation_started", "cert_profile_issuer_key_changed",
  # Activation lease
  "activation_lease_granted", "activation_custodian_authenticated",
  # Keystore / Keypair
  "keystore_configured",
  "keypair_access_granted", "keypair_access_revoked",
  # HSM
  "hsm_device_probed", "hsm_wizard_completed",
  # User / Profile
  "user_created", "user_updated", "user_deleted",
  "login", "logout",
  "password_changed", "profile_updated",
  # API keys
  "api_key_created", "api_key_revoked",
  # CA / RA instance
  "ca_instance_created", "ca_instance_renamed", "ca_instance_status_changed",
  "ra_instance_created", "ra_instance_status_changed",
  # Cert profiles
  "cert_profile_created", "cert_profile_updated",
  # Hierarchy
  "hierarchy_modified"
]
```

- [ ] **Step 4: Add `log/4` to `pki_audit_trail.ex`**

Add the following to `src/pki_audit_trail/lib/pki_audit_trail.ex`:

```elixir
@doc """
Write a hash-chained audit event to a tenant's per-tenant audit schema.
Only applicable to schema-mode tenants (those with a `t_<hex>_audit` Postgres schema).

Returns `{:ok, event}` on success. On any failure (missing table, DB error)
returns `{:error, reason}` and logs a warning — never raises.

  * `tenant_id` — UUID string of the tenant
  * `actor` — `%{actor_did: string, actor_role: string}` (node_name optional)
  * `action` — one of `PkiAuditTrail.Actions.all()`
  * `resource` — `%{resource_type: string, resource_id: string, details: map, ca_instance_id: string | nil}`
"""
def log(tenant_id, actor, action, resource)
    when is_binary(tenant_id) and is_map(actor) and is_binary(action) and is_map(resource) do
  prefix = audit_prefix(tenant_id)
  prev_hash = PkiAuditTrail.HashChainStore.get_or_seed(tenant_id)

  event_id = Ecto.UUID.generate()
  timestamp = DateTime.utc_now()

  attrs = %{
    event_id: event_id,
    timestamp: timestamp,
    node_name: Map.get(actor, :node_name, to_string(node())),
    actor_did: Map.fetch!(actor, :actor_did),
    actor_role: Map.get(actor, :actor_role, "unknown"),
    action: action,
    resource_type: Map.get(resource, :resource_type, ""),
    resource_id: to_string(Map.get(resource, :resource_id, "")),
    details: Map.get(resource, :details, %{}),
    ca_instance_id: Map.get(resource, :ca_instance_id),
    prev_hash: prev_hash
  }

  event_hash = PkiAuditTrail.Hasher.compute_hash(attrs)
  full_attrs = Map.put(attrs, :event_hash, event_hash)
  changeset = PkiAuditTrail.AuditEvent.changeset(%PkiAuditTrail.AuditEvent{}, full_attrs)

  Process.put(:pki_ecto_prefix, prefix)

  result =
    try do
      PkiAuditTrail.Repo.insert(changeset)
    after
      Process.delete(:pki_ecto_prefix)
    end

  case result do
    {:ok, event} ->
      PkiAuditTrail.HashChainStore.update(tenant_id, event_hash)
      {:ok, event}

    {:error, reason} ->
      require Logger
      Logger.warning("[audit_trail] per-tenant write failed tenant_id=#{tenant_id} reason=#{inspect(reason)}")
      {:error, reason}
  end
rescue
  e ->
    Process.delete(:pki_ecto_prefix)
    require Logger
    Logger.warning("[audit_trail] per-tenant write exception tenant_id=#{tenant_id} error=#{Exception.message(e)}")
    {:error, :exception}
end

defp audit_prefix(tenant_id) do
  hex = String.replace(tenant_id, "-", "")
  "t_#{hex}_audit"
end
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd src/pki_audit_trail && mix test test/pki_audit_trail/tenant_log_test.exs -v
```

Expected: 4 tests, 0 failures.

- [ ] **Step 6: Run full pki_audit_trail suite to catch regressions**

```bash
cd src/pki_audit_trail && mix test
```

Expected: 0 failures.

- [ ] **Step 7: Commit**

```bash
git add src/pki_audit_trail/lib/pki_audit_trail/actions.ex \
        src/pki_audit_trail/lib/pki_audit_trail.ex \
        src/pki_audit_trail/test/pki_audit_trail/tenant_log_test.exs
git commit -m "feat: PkiAuditTrail.log/4 — per-tenant hash-chained audit write + expand Actions list"
```

---

### Task 4: Wire per-tenant audit from `PlatformAudit.log/2`

**Files:**
- Modify: `src/pki_platform_engine/lib/pki_platform_engine/platform_audit.ex`
- Test: `src/pki_platform_engine/test/pki_platform_engine/platform_audit_tenant_test.exs`

- [ ] **Step 1: Write the failing test**

```elixir
# src/pki_platform_engine/test/pki_platform_engine/platform_audit_tenant_test.exs
defmodule PkiPlatformEngine.PlatformAuditTenantTest do
  use PkiPlatformEngine.DataCase, async: false

  alias PkiPlatformEngine.{PlatformAudit, Provisioner, TenantPrefix, PlatformRepo}
  import Ecto.Query

  setup do
    slug = "audit-wire-#{System.unique_integer([:positive])}"
    {:ok, tenant} = Provisioner.create_tenant("Audit Wire Test", slug, schema_mode: "schema")
    on_exit(fn -> Provisioner.delete_tenant(tenant.id) end)
    {:ok, tenant: tenant}
  end

  test "PlatformAudit.log writes to per-tenant audit_events for schema-mode tenant", %{tenant: tenant} do
    PlatformAudit.log("certificate_issued", %{
      tenant_id: tenant.id,
      actor_username: "alice",
      actor_role: "ca_admin",
      target_type: "certificate",
      target_id: "serial-123",
      portal: "ca"
    })

    prefix = TenantPrefix.audit_prefix(tenant.id)
    {:ok, result} = Ecto.Adapters.SQL.query(
      PlatformRepo,
      "SELECT action, actor_did FROM \"#{prefix}\".audit_events WHERE action = 'certificate_issued'",
      []
    )
    assert length(result.rows) == 1
    [[action, actor_did]] = result.rows
    assert action == "certificate_issued"
    assert actor_did == "alice"
  end

  test "PlatformAudit.log does not write to audit_events for beam-mode tenant" do
    {:ok, beam_tenant} = Provisioner.register_tenant(
      "Beam Tenant",
      "beam-#{System.unique_integer([:positive])}"
    )
    on_exit(fn ->
      PlatformRepo.delete_all(from t in PkiPlatformEngine.Tenant, where: t.id == ^beam_tenant.id)
    end)

    result = PlatformAudit.log("certificate_issued", %{
      tenant_id: beam_tenant.id,
      actor_username: "bob",
      target_type: "certificate",
      target_id: "serial-456",
      portal: "ca"
    })

    # Should succeed (writing to platform_audit_events is fine)
    assert {:ok, _} = result
    # No crash, no per-tenant Postgres write attempted
  end

  test "PlatformAudit.log succeeds even if per-tenant write fails" do
    bad_tenant_id = Ecto.UUID.generate()

    result = PlatformAudit.log("certificate_issued", %{
      tenant_id: bad_tenant_id,
      actor_username: "charlie",
      portal: "ca"
    })

    # platform_audit_events write should succeed
    assert {:ok, _} = result
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd src/pki_platform_engine && mix test test/pki_platform_engine/platform_audit_tenant_test.exs -v
```

Expected: FAIL — per-tenant write not wired yet.

- [ ] **Step 3: Modify `PlatformAudit.log/2`**

Edit `src/pki_platform_engine/lib/pki_platform_engine/platform_audit.ex`. Add these dependencies at the top of the module and update `log/2`:

```elixir
defmodule PkiPlatformEngine.PlatformAudit do
  @moduledoc """
  Audit logging for platform-level operations.
  Writes to platform_audit_events and, for schema-mode tenants, also writes
  a hash-chained event to the tenant's per-tenant audit schema.
  """

  import Ecto.Query
  require Logger
  alias PkiPlatformEngine.{PlatformRepo, PlatformAuditEvent, Tenant}

  def log(action, attrs \\ %{}) do
    result =
      %PlatformAuditEvent{}
      |> PlatformAuditEvent.changeset(Map.merge(attrs, %{action: action, timestamp: DateTime.utc_now()}))
      |> PlatformRepo.insert()

    case Map.get(attrs, :tenant_id) do
      nil -> :ok
      tenant_id -> maybe_write_tenant_audit(tenant_id, action, attrs)
    end

    result
  end

  # ... (keep list_events/1 unchanged)

  defp maybe_write_tenant_audit(tenant_id, action, attrs) do
    case PlatformRepo.get(Tenant, tenant_id) do
      %{schema_mode: "schema"} ->
        actor = %{
          actor_did: Map.get(attrs, :actor_username, "system"),
          actor_role: Map.get(attrs, :actor_role, "unknown"),
          node_name: to_string(node())
        }
        resource = %{
          resource_type: Map.get(attrs, :target_type, infer_resource_type(action)),
          resource_id: to_string(Map.get(attrs, :target_id, "")),
          details: Map.drop(attrs, ~w[tenant_id actor_id actor_username actor_role target_type target_id portal]a),
          ca_instance_id: Map.get(attrs, :ca_instance_id)
        }
        PkiAuditTrail.log(tenant_id, actor, action, resource)

      _ ->
        :ok
    end
  rescue
    e ->
      Logger.warning("[platform_audit] per-tenant audit failed tenant_id=#{tenant_id} error=#{Exception.message(e)}")
      :ok
  end

  defp infer_resource_type(action) do
    cond do
      String.contains?(action, "certificate") -> "certificate"
      String.contains?(action, "csr") -> "csr"
      String.contains?(action, "ceremony") -> "ceremony"
      String.contains?(action, "issuer_key") or String.contains?(action, "key") -> "issuer_key"
      String.contains?(action, "ca_instance") -> "ca_instance"
      String.contains?(action, "keystore") -> "keystore"
      String.contains?(action, "user") or String.contains?(action, "profile") or String.contains?(action, "password") -> "user"
      String.contains?(action, "api_key") -> "api_key"
      true -> "general"
    end
  end
end
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd src/pki_platform_engine && mix test test/pki_platform_engine/platform_audit_tenant_test.exs -v
```

Expected: 3 tests, 0 failures.

- [ ] **Step 5: Run full pki_platform_engine test suite**

```bash
cd src/pki_platform_engine && mix test
```

Expected: 0 failures.

- [ ] **Step 6: Commit**

```bash
git add src/pki_platform_engine/lib/pki_platform_engine/platform_audit.ex \
        src/pki_platform_engine/test/pki_platform_engine/platform_audit_tenant_test.exs
git commit -m "feat: wire per-tenant hash-chained audit from PlatformAudit.log for schema-mode tenants"
```

---

### Task 5: Mix task to patch existing schema-mode tenants on the VPS

**Files:**
- Create: `src/pki_platform_engine/lib/mix/tasks/pki.migrate_existing_tenants.ex`
- Test: manual verification on VPS (idempotency check)

- [ ] **Step 1: Create the mix task**

```elixir
# src/pki_platform_engine/lib/mix/tasks/pki.migrate_existing_tenants.ex
defmodule Mix.Tasks.Pki.MigrateExistingTenants do
  use Mix.Task
  require Logger

  @shortdoc "Idempotent: add audit + validation schemas to existing schema-mode tenants"

  @moduledoc """
  Run after deploying the per-tenant audit/validation schema changes to a VPS
  with existing schema-mode tenants. Safe to run multiple times — all SQL
  uses CREATE IF NOT EXISTS.

  Usage:
    mix pki.migrate_existing_tenants
  """

  @impl Mix.Task
  def run(_args) do
    Mix.Task.run("app.start")

    import Ecto.Query
    alias PkiPlatformEngine.{PlatformRepo, Tenant, TenantPrefix, Provisioner}

    tenants =
      PlatformRepo.all(from t in Tenant, where: t.schema_mode == "schema", order_by: t.inserted_at)

    IO.puts("Found #{length(tenants)} schema-mode tenant(s).")

    for tenant <- tenants do
      IO.write("  #{tenant.slug} (#{tenant.id}) ... ")
      prefixes = TenantPrefix.all_prefixes(tenant.id)

      errors =
        [
          fn -> Provisioner.ensure_schema_exists(prefixes.audit_prefix) end,
          fn -> Provisioner.apply_schema_sql("tenant_audit_schema.sql", "audit", prefixes.audit_prefix) end,
          fn -> Provisioner.ensure_schema_exists(prefixes.validation_prefix) end,
          fn -> Provisioner.apply_schema_sql("tenant_validation_schema.sql", "validation", prefixes.validation_prefix) end
        ]
        |> Enum.flat_map(fn f ->
          try do
            f.()
            []
          rescue
            e -> [Exception.message(e)]
          end
        end)

      if errors == [] do
        IO.puts("OK")
      else
        IO.puts("FAILED")
        Enum.each(errors, &IO.puts("    #{&1}"))
      end
    end

    IO.puts("Done.")
  end
end
```

- [ ] **Step 2: Verify the task is runnable (local dry-run)**

```bash
cd src/pki_platform_engine && mix pki.migrate_existing_tenants
```

Expected output (no existing schema-mode tenants in local dev):
```
Found 0 schema-mode tenant(s).
Done.
```

- [ ] **Step 3: Test idempotency by provisioning a test tenant and running twice**

```bash
# In iex -S mix (pki_platform_engine directory):
{:ok, t} = PkiPlatformEngine.Provisioner.create_tenant("Idem Test", "idem-test", schema_mode: "schema")
# Then in shell:
mix pki.migrate_existing_tenants
# Expected: "  idem-test (...) ... OK"
mix pki.migrate_existing_tenants
# Expected: same output, no errors (idempotent)
PkiPlatformEngine.Provisioner.delete_tenant(t.id)
```

- [ ] **Step 4: Commit**

```bash
git add src/pki_platform_engine/lib/mix/tasks/pki.migrate_existing_tenants.ex
git commit -m "feat: mix pki.migrate_existing_tenants — patch existing schema-mode tenants with audit + validation schemas"
```

---

## Self-Review

**Spec coverage:**
- ✅ `audit_events` table created per-tenant at provisioning — Task 1
- ✅ Hash chain tracks per-tenant prev_hash — Task 2
- ✅ `PkiAuditTrail.log/4` writes hash-chained events — Task 3
- ✅ All `pki_tenant_web` audit action strings are now valid in `Actions` — Task 3
- ✅ Events routed from `PlatformAudit.log/2` for schema-mode tenants — Task 4
- ✅ Per-tenant validation schema provisioned — Task 1
- ✅ VPS existing-tenant migration tooling — Task 5
- ✅ BEAM-mode tenants unaffected (no Postgres schemas, `maybe_write_tenant_audit` no-ops on `schema_mode != "schema"`) — Task 4
- ✅ Process dict prefix cleaned up in `try/after` — Task 3

**Out of scope (follow-up):**
- `PkiValidation.Repo` with per-tenant prefix routing for OCSP/CRL — validation tables exist but code still uses Mnesia
- `certificate_signing.ex` TODO — direct CA-engine audit calls — deferred until system-actor DID is provisioned per tenant

---

Plan complete and saved to `docs/superpowers/plans/2026-04-27-per-tenant-audit-validation.md`.

**Two execution options:**

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, two-stage review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

Which approach?
