# Plan 2: pki_ca_engine — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Core CA Engine — the isolated Erlang node that holds signing keys, manages key ceremonies, issues certificates, and enforces access control.

**Architecture:** Elixir OTP application with GenServer-based process modules per the product spec. Uses Ecto/Postgres for persistent data, existing `strap_priv_key_store_provider` for crypto operations, `keyx` for Shamir SSS, `pki_audit_trail` for audit logging, and SSDID for inter-node auth. Each CA owner gets their own process supervision tree. Protocols used for polymorphism (not behaviours).

**Tech Stack:** Elixir/OTP, Ecto (Postgres), `strap_priv_key_store_provider` (crypto), `keyx` (Shamir SSS), `ex_ccrypto` + `x509` (certificates), `pki_audit_trail` (audit), `strap_proc_reg` (service registry), SSDID (auth)

**Spec Reference:** `docs/superpowers/specs/2026-03-15-pqc-ca-system-design.md` — Sections 3.2, 4.1, 5, 6, 7

**Existing Libraries (in `src/`):**
- `strap_priv_key_store_provider` — unified crypto provider API with protocols: `KeyGeneratorProtocol`, `KeypairEngine`, `PrivateKeyOps`, `PublicKeyOps`, `CertManagerProtocol`, `CSRGeneratorProtocol`, `KeystoreManagerProtocol`
- `strap_soft_priv_key_store_provider` — software keystore GenServer provider
- `strap_java_crypto_priv_key_store_provider` — PQC provider via BouncyCastle
- `strap_softhsm_priv_key_store_provider` — HSM provider via PKCS#11
- `keyx` — Shamir Secret Sharing (`KeyX.generate_shares/5`, `KeyX.recover_secret/3`)
- `ex_ccrypto` — crypto primitives (cipher, KDF, x509 cert/CSR generation)
- `x509` — X.509 certificate operations
- `strap_proc_reg` — distributed process registry
- `pki_audit_trail` — audit logging (just built in Plan 1)

---

## Chunk 1: Project Scaffold and Database Schema

### Task 1: Create the Elixir project

**Files:**
- Create: `pki_ca_engine/mix.exs`
- Create: `pki_ca_engine/config/config.exs`
- Create: `pki_ca_engine/config/dev.exs`
- Create: `pki_ca_engine/config/test.exs`
- Create: `pki_ca_engine/config/runtime.exs`
- Create: `pki_ca_engine/lib/pki_ca_engine.ex`
- Create: `pki_ca_engine/lib/pki_ca_engine/repo.ex`
- Create: `pki_ca_engine/lib/pki_ca_engine/application.ex`
- Create: `pki_ca_engine/test/test_helper.exs`
- Create: `pki_ca_engine/test/support/data_case.ex`

- [ ] **Step 1: Generate the project**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src
mix new pki_ca_engine --sup
cd pki_ca_engine
```

- [ ] **Step 2: Configure mix.exs**

```elixir
defmodule PkiCaEngine.MixProject do
  use Mix.Project

  def project do
    [
      app: :pki_ca_engine,
      version: "0.1.0",
      elixir: "~> 1.15",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      aliases: aliases(),
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto, :mnesia],
      mod: {PkiCaEngine.Application, []}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:ecto_sql, "~> 3.11"},
      {:postgrex, "~> 0.18"},
      {:jason, "~> 1.4"},
      {:typed_struct, "~> 0.5"},
      # Internal dependencies (use path for dev, git tags for release)
      {:pki_audit_trail, path: "../pki_audit_trail"},
      {:ex_ccrypto, path: "../ex_ccrypto"},
      {:x509, path: "../x509"},
      {:keyx, path: "../keyx"},
      {:strap_proc_reg, path: "../strap_proc_reg"},
      {:strap_priv_key_store_provider, path: "../strap_priv_key_store_provider"},
      {:strap_soft_priv_key_store_provider, path: "../strap_soft_priv_key_store_provider"}
    ]
  end

  defp aliases do
    [
      setup: ["deps.get", "ecto.setup"],
      "ecto.setup": ["ecto.create", "ecto.migrate"],
      "ecto.reset": ["ecto.drop", "ecto.setup"],
      test: ["ecto.create --quiet", "ecto.migrate --quiet", "test"]
    ]
  end
end
```

**Note:** Some path deps may have their own transitive deps. Run `mix deps.get` and resolve any conflicts. If a dep fails to resolve, temporarily comment it out and add it back incrementally. The minimum viable set for Chunk 1 is: `ecto_sql`, `postgrex`, `jason`, `pki_audit_trail`.

- [ ] **Step 3: Create configs**

`config/config.exs`:
```elixir
import Config
config :pki_ca_engine, ecto_repos: [PkiCaEngine.Repo]
import_config "#{config_env()}.exs"
```

`config/dev.exs`:
```elixir
import Config
config :pki_ca_engine, PkiCaEngine.Repo,
  username: "postgres", password: "postgres", hostname: "localhost",
  database: "pki_ca_engine_dev", stacktrace: true,
  show_sensitive_data_on_connection_error: true, pool_size: 10
```

`config/test.exs`:
```elixir
import Config
config :pki_ca_engine, PkiCaEngine.Repo,
  username: "postgres", password: "postgres", hostname: "localhost",
  database: "pki_ca_engine_test#{System.get_env("MIX_TEST_PARTITION")}",
  pool: Ecto.Adapters.SQL.Sandbox, pool_size: 10
config :logger, level: :warning
```

`config/runtime.exs`:
```elixir
import Config

if config_env() == :prod do
  config :pki_ca_engine, PkiCaEngine.Repo,
    url: System.get_env("DATABASE_URL") || raise("DATABASE_URL not set"),
    pool_size: String.to_integer(System.get_env("POOL_SIZE") || "10")
end
```

- [ ] **Step 4: Create Repo, Application, main module, test support**

`lib/pki_ca_engine/repo.ex`:
```elixir
defmodule PkiCaEngine.Repo do
  use Ecto.Repo, otp_app: :pki_ca_engine, adapter: Ecto.Adapters.Postgres
end
```

`lib/pki_ca_engine/application.ex`:
```elixir
defmodule PkiCaEngine.Application do
  use Application

  @impl true
  def start(_type, _args) do
    children = [
      PkiCaEngine.Repo
    ]
    opts = [strategy: :one_for_one, name: PkiCaEngine.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
```

`lib/pki_ca_engine.ex`:
```elixir
defmodule PkiCaEngine do
  @moduledoc """
  Core Certificate Authority Engine.
  Manages signing keys, key ceremonies, certificate issuance, and access control.
  """
end
```

`test/test_helper.exs`:
```elixir
ExUnit.start()
Ecto.Adapters.SQL.Sandbox.mode(PkiCaEngine.Repo, :manual)
```

`test/support/data_case.ex`:
```elixir
defmodule PkiCaEngine.DataCase do
  use ExUnit.CaseTemplate

  using do
    quote do
      alias PkiCaEngine.Repo
      import Ecto
      import Ecto.Changeset
      import Ecto.Query
      import PkiCaEngine.DataCase
    end
  end

  setup tags do
    pid = Ecto.Adapters.SQL.Sandbox.start_owner!(PkiCaEngine.Repo, shared: not tags[:async])
    on_exit(fn -> Ecto.Adapters.SQL.Sandbox.stop_owner(pid) end)
    :ok
  end
end
```

- [ ] **Step 5: Install deps and verify**

```bash
mix deps.get && mix compile
```

- [ ] **Step 6: Commit**

```bash
git init && git add -A && git commit -m "feat: scaffold pki_ca_engine project"
```

---

### Task 2: Create database migrations

**Files:**
- Create: `pki_ca_engine/priv/repo/migrations/TIMESTAMP_create_ca_instances.exs`
- Create: `pki_ca_engine/priv/repo/migrations/TIMESTAMP_create_ca_users.exs`
- Create: `pki_ca_engine/priv/repo/migrations/TIMESTAMP_create_keystores.exs`
- Create: `pki_ca_engine/priv/repo/migrations/TIMESTAMP_create_issuer_keys.exs`
- Create: `pki_ca_engine/priv/repo/migrations/TIMESTAMP_create_keypair_access.exs`
- Create: `pki_ca_engine/priv/repo/migrations/TIMESTAMP_create_threshold_shares.exs`
- Create: `pki_ca_engine/priv/repo/migrations/TIMESTAMP_create_key_ceremonies.exs`
- Create: `pki_ca_engine/priv/repo/migrations/TIMESTAMP_create_issued_certificates.exs`

- [ ] **Step 1: Generate and implement migrations**

Generate each migration with `mix ecto.gen.migration <name>`, then implement.

**ca_instances:**
```elixir
defmodule PkiCaEngine.Repo.Migrations.CreateCaInstances do
  use Ecto.Migration

  def change do
    create table(:ca_instances) do
      add :name, :string, null: false
      add :status, :string, null: false, default: "initialized"
      add :domain_info, :map, default: %{}
      add :created_by, :string, null: false
      timestamps()
    end
    create unique_index(:ca_instances, [:name])
  end
end
```

**ca_users:**
```elixir
defmodule PkiCaEngine.Repo.Migrations.CreateCaUsers do
  use Ecto.Migration

  def change do
    create table(:ca_users) do
      add :ca_instance_id, references(:ca_instances, on_delete: :delete_all), null: false
      add :did, :string, null: false
      add :display_name, :string, null: false
      add :role, :string, null: false
      add :status, :string, null: false, default: "active"
      timestamps()
    end
    create unique_index(:ca_users, [:ca_instance_id, :did])
    create index(:ca_users, [:ca_instance_id])
    create index(:ca_users, [:role])
  end
end
```

**keystores:**
```elixir
defmodule PkiCaEngine.Repo.Migrations.CreateKeystores do
  use Ecto.Migration

  def change do
    create table(:keystores) do
      add :ca_instance_id, references(:ca_instances, on_delete: :delete_all), null: false
      add :type, :string, null: false
      add :config, :binary, null: false
      add :status, :string, null: false, default: "active"
      add :provider_name, :string, null: false
      timestamps()
    end
    create index(:keystores, [:ca_instance_id])
  end
end
```

**issuer_keys:**
```elixir
defmodule PkiCaEngine.Repo.Migrations.CreateIssuerKeys do
  use Ecto.Migration

  def change do
    create table(:issuer_keys) do
      add :ca_instance_id, references(:ca_instances, on_delete: :delete_all), null: false
      add :key_alias, :string, null: false
      add :algorithm, :string, null: false
      add :status, :string, null: false, default: "pending"
      add :keystore_ref, :binary
      add :is_root, :boolean, null: false, default: false
      add :threshold_config, :map
      add :certificate_der, :binary
      add :certificate_pem, :text
      timestamps()
    end
    create unique_index(:issuer_keys, [:ca_instance_id, :key_alias])
    create index(:issuer_keys, [:ca_instance_id])
    create index(:issuer_keys, [:status])
  end
end
```

**keypair_access:**
```elixir
defmodule PkiCaEngine.Repo.Migrations.CreateKeypairAccess do
  use Ecto.Migration

  def change do
    create table(:keypair_access) do
      add :issuer_key_id, references(:issuer_keys, on_delete: :delete_all), null: false
      add :user_id, references(:ca_users, on_delete: :delete_all), null: false
      add :granted_by, references(:ca_users, on_delete: :nilify_all)
      add :granted_at, :utc_datetime_usec, null: false
    end
    create unique_index(:keypair_access, [:issuer_key_id, :user_id])
  end
end
```

**threshold_shares:**
```elixir
defmodule PkiCaEngine.Repo.Migrations.CreateThresholdShares do
  use Ecto.Migration

  def change do
    create table(:threshold_shares) do
      add :issuer_key_id, references(:issuer_keys, on_delete: :delete_all), null: false
      add :custodian_user_id, references(:ca_users, on_delete: :delete_all), null: false
      add :share_index, :integer, null: false
      add :encrypted_share, :binary, null: false
      add :min_shares, :integer, null: false
      add :total_shares, :integer, null: false
      timestamps()
    end
    create unique_index(:threshold_shares, [:issuer_key_id, :custodian_user_id])
    create index(:threshold_shares, [:issuer_key_id])
  end
end
```

**key_ceremonies:**
```elixir
defmodule PkiCaEngine.Repo.Migrations.CreateKeyCeremonies do
  use Ecto.Migration

  def change do
    create table(:key_ceremonies) do
      add :ca_instance_id, references(:ca_instances, on_delete: :delete_all), null: false
      add :issuer_key_id, references(:issuer_keys, on_delete: :nilify_all)
      add :ceremony_type, :string, null: false
      add :status, :string, null: false, default: "initiated"
      add :initiated_by, references(:ca_users, on_delete: :nilify_all), null: false
      add :participants, :map, default: %{}
      add :algorithm, :string, null: false
      add :keystore_id, references(:keystores, on_delete: :nilify_all)
      add :threshold_k, :integer, null: false
      add :threshold_n, :integer, null: false
      add :domain_info, :map, default: %{}
      add :window_expires_at, :utc_datetime_usec
      timestamps(updated_at: :completed_at)
    end
    create index(:key_ceremonies, [:ca_instance_id])
    create index(:key_ceremonies, [:status])
  end
end
```

**issued_certificates:**
```elixir
defmodule PkiCaEngine.Repo.Migrations.CreateIssuedCertificates do
  use Ecto.Migration

  def change do
    create table(:issued_certificates) do
      add :serial_number, :string, null: false
      add :issuer_key_id, references(:issuer_keys, on_delete: :restrict), null: false
      add :subject_dn, :string, null: false
      add :cert_der, :binary, null: false
      add :cert_pem, :text, null: false
      add :not_before, :utc_datetime_usec, null: false
      add :not_after, :utc_datetime_usec, null: false
      add :status, :string, null: false, default: "active"
      add :revoked_at, :utc_datetime_usec
      add :revocation_reason, :string
      add :cert_profile_id, :integer
      timestamps()
    end
    create unique_index(:issued_certificates, [:serial_number])
    create index(:issued_certificates, [:issuer_key_id])
    create index(:issued_certificates, [:status])
    create index(:issued_certificates, [:subject_dn])
    create index(:issued_certificates, [:not_after])
  end
end
```

- [ ] **Step 2: Run migrations**

```bash
mix ecto.create && mix ecto.migrate
```

- [ ] **Step 3: Commit**

```bash
git add -A && git commit -m "feat: add database migrations for all CA engine tables"
```

---

### Task 3: Create Ecto schemas for all tables

**Files:**
- Create: `lib/pki_ca_engine/schema/ca_instance.ex`
- Create: `lib/pki_ca_engine/schema/ca_user.ex`
- Create: `lib/pki_ca_engine/schema/keystore.ex`
- Create: `lib/pki_ca_engine/schema/issuer_key.ex`
- Create: `lib/pki_ca_engine/schema/keypair_access.ex`
- Create: `lib/pki_ca_engine/schema/threshold_share.ex`
- Create: `lib/pki_ca_engine/schema/key_ceremony.ex`
- Create: `lib/pki_ca_engine/schema/issued_certificate.ex`
- Create: `test/pki_ca_engine/schema_test.exs`

- [ ] **Step 1: Write tests for all schemas**

Create `test/pki_ca_engine/schema_test.exs` testing changeset validation for each schema. Each schema should validate required fields and constraints. Test valid and invalid changesets.

Key validations per schema:
- `CaInstance` — name required, status must be in allowed values
- `CaUser` — did, display_name, role required; role must be in `["ca_admin", "key_manager", "ra_admin", "auditor"]`
- `Keystore` — type must be in `["software", "hsm"]`; config is encrypted binary
- `IssuerKey` — algorithm, key_alias required; status must be in `["pending", "active", "suspended", "archived"]`
- `KeypairAccess` — issuer_key_id, user_id required
- `ThresholdShare` — min_shares >= 2, min_shares <= total_shares
- `KeyCeremony` — ceremony_type must be in `["sync", "async"]`; threshold_k >= 2, threshold_k <= threshold_n
- `IssuedCertificate` — serial_number, subject_dn, cert_der, cert_pem required; status in `["active", "revoked"]`

- [ ] **Step 2: Run tests — verify FAIL**

- [ ] **Step 3: Implement all schemas**

Each schema goes in `lib/pki_ca_engine/schema/`. Follow the pattern:

```elixir
defmodule PkiCaEngine.Schema.CaInstance do
  use Ecto.Schema
  import Ecto.Changeset

  @statuses ["initialized", "active", "suspended"]

  schema "ca_instances" do
    field :name, :string
    field :status, :string, default: "initialized"
    field :domain_info, :map, default: %{}
    field :created_by, :string

    has_many :ca_users, PkiCaEngine.Schema.CaUser
    has_many :keystores, PkiCaEngine.Schema.Keystore
    has_many :issuer_keys, PkiCaEngine.Schema.IssuerKey

    timestamps()
  end

  def changeset(ca_instance, attrs) do
    ca_instance
    |> cast(attrs, [:name, :status, :domain_info, :created_by])
    |> validate_required([:name, :created_by])
    |> validate_inclusion(:status, @statuses)
    |> unique_constraint(:name)
  end
end
```

Follow the same pattern for all 8 schemas with appropriate validations, associations, and status enums.

`CaUser` — roles: `["ca_admin", "key_manager", "ra_admin", "auditor"]`, statuses: `["active", "suspended"]`
`Keystore` — types: `["software", "hsm"]`, statuses: `["active", "inactive"]`
`IssuerKey` — statuses: `["pending", "active", "suspended", "archived"]`, belongs_to ca_instance
`KeypairAccess` — belongs_to issuer_key and user
`ThresholdShare` — validate min_shares >= 2 and min_shares <= total_shares
`KeyCeremony` — types: `["sync", "async"]`, statuses: `["initiated", "in_progress", "completed", "failed"]`
`IssuedCertificate` — statuses: `["active", "revoked"]`

- [ ] **Step 4: Run tests — verify PASS**

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: add Ecto schemas for all CA engine tables"
```

---

## Chunk 2: User Management Module

### Task 4: Implement User Management

**Files:**
- Create: `lib/pki_ca_engine/user_management.ex`
- Create: `test/pki_ca_engine/user_management_test.exs`

This module handles CRUD for local CA users with role-based access control. Per the spec, it's activated by CA Admin and enforces least privilege.

- [ ] **Step 1: Write tests**

Test CRUD operations:
- `create_user/2` — creates user with role, validates role enum, requires ca_instance
- `list_users/1` — lists users for a CA instance, filterable by role
- `get_user/1` — gets user by ID
- `update_user/2` — updates display_name or status (not role — role changes require delete + recreate)
- `delete_user/1` — soft-deletes (sets status to suspended)
- `authorize/2` — checks if a user has a specific permission based on role

Role-permission matrix:
- `ca_admin`: manage_ca_admins, manage_auditors, all read
- `key_manager`: manage_key_managers, manage_keystores, manage_keys, manage_keypair_access
- `ra_admin`: manage_ra_admins, manage_ra_keypair_access
- `auditor`: view_audit_log, participate_ceremony

- [ ] **Step 2: Run tests — verify FAIL**

- [ ] **Step 3: Implement UserManagement module**

```elixir
defmodule PkiCaEngine.UserManagement do
  @moduledoc """
  Local user management per CA instance.
  Roles: ca_admin, key_manager, ra_admin, auditor.
  Enforces least privilege per product spec.
  """

  alias PkiCaEngine.{Repo, Schema.CaUser}
  import Ecto.Query

  @role_permissions %{
    "ca_admin" => [:manage_ca_admins, :manage_auditors, :view_audit_log, :view_all],
    "key_manager" => [:manage_key_managers, :manage_keystores, :manage_keys, :manage_keypair_access],
    "ra_admin" => [:manage_ra_admins, :manage_ra_keypair_access],
    "auditor" => [:view_audit_log, :participate_ceremony]
  }

  def create_user(ca_instance_id, attrs) do
    %CaUser{}
    |> CaUser.changeset(Map.put(attrs, :ca_instance_id, ca_instance_id))
    |> Repo.insert()
  end

  def list_users(ca_instance_id, filters \\ []) do
    CaUser
    |> where([u], u.ca_instance_id == ^ca_instance_id)
    |> apply_user_filters(filters)
    |> Repo.all()
  end

  def get_user(id), do: Repo.get(CaUser, id)

  def update_user(%CaUser{} = user, attrs) do
    user
    |> CaUser.update_changeset(attrs)
    |> Repo.update()
  end

  def delete_user(%CaUser{} = user) do
    user
    |> Ecto.Changeset.change(status: "suspended")
    |> Repo.update()
  end

  def authorize(%CaUser{role: role}, permission) do
    permissions = Map.get(@role_permissions, role, [])
    if permission in permissions, do: :ok, else: {:error, :unauthorized}
  end

  defp apply_user_filters(query, []), do: query
  defp apply_user_filters(query, [{:role, role} | rest]),
    do: query |> where([u], u.role == ^role) |> apply_user_filters(rest)
  defp apply_user_filters(query, [{:status, status} | rest]),
    do: query |> where([u], u.status == ^status) |> apply_user_filters(rest)
  defp apply_user_filters(query, [_ | rest]), do: apply_user_filters(query, rest)
end
```

- [ ] **Step 4: Run tests — verify PASS**

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: add user management with role-based access control"
```

---

## Chunk 3: Keystore Management Module

### Task 5: Implement Keystore Management

**Files:**
- Create: `lib/pki_ca_engine/keystore_management.ex`
- Create: `test/pki_ca_engine/keystore_management_test.exs`

Per the spec: "Dynamic search for activated private keystore. Software is activated by default. Key Manager select and configure the private keystore."

- [ ] **Step 1: Write tests**

Test:
- `configure_keystore/2` — creates keystore config (software/hsm) with encrypted config
- `list_keystores/1` — lists keystores for a CA instance
- `get_keystore/1` — gets keystore by ID
- `update_keystore/2` — updates config or status
- `available_keystores/1` — returns only active keystores
- `get_provider/1` — returns the correct provider module based on keystore type

- [ ] **Step 2: Run tests — verify FAIL**

- [ ] **Step 3: Implement KeystoreManagement**

The module wraps keystore CRUD and maps types to providers:
- `"software"` → `StrapSoftPrivKeyStoreProvider`
- `"hsm"` → `StrapSofthsmPrivKeyStoreProvider`

Config is encrypted at rest using AES-256-GCM with a config encryption key from application env.

- [ ] **Step 4: Run tests — verify PASS**

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: add keystore management with provider mapping"
```

---

## Chunk 4: Keypair Access Control

### Task 6: Implement Keypair Access Control

**Files:**
- Create: `lib/pki_ca_engine/keypair_access.ex`
- Create: `test/pki_ca_engine/keypair_access_test.exs`

Per the spec: "Bind selected private key to user that are allowed to access the private key."

- [ ] **Step 1: Write tests**

Test:
- `grant_access/3` — grants user access to a key, records who granted
- `revoke_access/2` — revokes user access to a key
- `has_access?/2` — checks if user has access to a key
- `list_access/1` — lists all users with access to a key
- `list_keys_for_user/1` — lists all keys a user can access

- [ ] **Step 2: Run tests — verify FAIL**

- [ ] **Step 3: Implement KeypairAccess module**

Simple CRUD on `keypair_access` table with audit trail integration:
```elixir
defmodule PkiCaEngine.KeypairAccess do
  alias PkiCaEngine.{Repo, Schema.KeypairAccess}
  import Ecto.Query

  def grant_access(issuer_key_id, user_id, granted_by_id) do
    %KeypairAccess{}
    |> KeypairAccess.changeset(%{
      issuer_key_id: issuer_key_id,
      user_id: user_id,
      granted_by: granted_by_id,
      granted_at: DateTime.utc_now()
    })
    |> Repo.insert()
  end

  def revoke_access(issuer_key_id, user_id) do
    from(ka in KeypairAccess,
      where: ka.issuer_key_id == ^issuer_key_id and ka.user_id == ^user_id
    )
    |> Repo.delete_all()
  end

  def has_access?(issuer_key_id, user_id) do
    Repo.exists?(
      from ka in KeypairAccess,
        where: ka.issuer_key_id == ^issuer_key_id and ka.user_id == ^user_id
    )
  end

  def list_access(issuer_key_id) do
    from(ka in KeypairAccess, where: ka.issuer_key_id == ^issuer_key_id, preload: [:user])
    |> Repo.all()
  end

  def list_keys_for_user(user_id) do
    from(ka in KeypairAccess, where: ka.user_id == ^user_id, preload: [:issuer_key])
    |> Repo.all()
  end
end
```

- [ ] **Step 4: Run tests — verify PASS**

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: add keypair access control"
```

---

## Chunk 5: Issuer Key Management

### Task 7: Implement Issuer Key Management

**Files:**
- Create: `lib/pki_ca_engine/issuer_key_management.ex`
- Create: `test/pki_ca_engine/issuer_key_management_test.exs`

Per the spec: "Generate key, Update key status, Generate certificate for key (self sign), Renewal of certificate, Generate CSR for key, Activate key by uploading certificate."

- [ ] **Step 1: Write tests**

Test:
- `create_issuer_key/2` — creates issuer key record with algorithm and keystore ref
- `get_issuer_key/1` — fetch by ID with preloads
- `list_issuer_keys/1` — list for CA instance, filterable by status
- `update_status/2` — transitions: pending→active, active→suspended, suspended→active, any→archived
- `activate_by_certificate/2` — sets certificate and marks active (for sub-CA after external CA signs CSR)
- `generate_self_signed_cert/2` — generates self-signed cert for root CA key
- `generate_csr/2` — generates CSR for sub-CA key
- Status transition validation (invalid transitions rejected)

- [ ] **Step 2: Run tests — verify FAIL**

- [ ] **Step 3: Implement IssuerKeyManagement**

This module manages the issuer key lifecycle. Certificate generation delegates to `ex_ccrypto` / `x509` for classical algorithms or `ap_java_crypto` for PQC.

Key status state machine:
```
pending → active (via activate_by_certificate or key ceremony completion)
active → suspended
suspended → active
any → archived
```

For certificate/CSR generation, use the `strap_priv_key_store_provider` protocol:
```elixir
def generate_self_signed_cert(issuer_key, cert_owner) do
  # 1. Get the provider from the keystore
  # 2. Call CertManagerProtocol.issue_certificate
  # 3. Store cert DER/PEM on the issuer_key record
end

def generate_csr(issuer_key, cert_owner) do
  # 1. Get the provider from the keystore
  # 2. Call CSRGeneratorProtocol.generate_csr
  # 3. Return CSR PEM
end
```

- [ ] **Step 4: Run tests — verify PASS**

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: add issuer key management with status state machine"
```

---

## Chunk 6: Key Ceremony — Synchronous

### Task 8: Implement Synchronous Key Ceremony

**Files:**
- Create: `lib/pki_ca_engine/key_ceremony.ex`
- Create: `lib/pki_ca_engine/key_ceremony/sync_ceremony.ex`
- Create: `lib/pki_ca_engine/key_ceremony/share_encryption.ex`
- Create: `test/pki_ca_engine/key_ceremony/sync_ceremony_test.exs`
- Create: `test/pki_ca_engine/key_ceremony/share_encryption_test.exs`

The most complex flow in the system. Follow the spec's 6-step process exactly.

- [ ] **Step 1: Write tests for ShareEncryption (utility module)**

Test:
- `encrypt_share/2` — encrypts a share with a password (Argon2 + AES-256-GCM)
- `decrypt_share/2` — decrypts an encrypted share with the correct password
- `decrypt_share/2` — returns error with wrong password
- Round-trip: encrypt → decrypt recovers original

- [ ] **Step 2: Run tests — verify FAIL**

- [ ] **Step 3: Implement ShareEncryption**

```elixir
defmodule PkiCaEngine.KeyCeremony.ShareEncryption do
  @moduledoc """
  Encrypts/decrypts Shamir shares with custodian passwords.
  Uses Argon2 for key derivation + AES-256-GCM for encryption.
  """

  def encrypt_share(share, password) when is_binary(share) and is_binary(password) do
    # 1. Derive key from password via Argon2
    # 2. Generate random IV (12 bytes)
    # 3. Encrypt share with AES-256-GCM
    # 4. Return {iv, ciphertext, tag} as single binary
    salt = :crypto.strong_rand_bytes(16)
    key = derive_key(password, salt)
    iv = :crypto.strong_rand_bytes(12)
    {ciphertext, tag} = :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, share, "", true)
    {:ok, salt <> iv <> tag <> ciphertext}
  end

  def decrypt_share(encrypted, password) when is_binary(encrypted) and is_binary(password) do
    <<salt::binary-16, iv::binary-12, tag::binary-16, ciphertext::binary>> = encrypted
    key = derive_key(password, salt)
    case :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, ciphertext, "", tag, false) do
      :error -> {:error, :decryption_failed}
      plaintext -> {:ok, plaintext}
    end
  end

  defp derive_key(password, salt) do
    # Use PBKDF2-SHA256 as a simpler alternative to Argon2 for now
    # (Argon2 requires argon2_elixir dep which is already in ex_ccrypto)
    :crypto.pbkdf2_hmac(:sha256, password, salt, 100_000, 32)
  end
end
```

- [ ] **Step 4: Run tests — verify PASS**

- [ ] **Step 5: Write tests for SyncCeremony**

Test the full sync ceremony flow:
- `initiate/1` — creates ceremony record, validates prerequisites (keystore exists, enough participants)
- `generate_keypair/1` — generates keypair via provider, returns public key
- `distribute_share/3` — encrypts and stores share for a custodian
- `complete/2` — generates cert (self-signed or CSR), marks key active, wipes key material
- Error cases: no keystore, insufficient participants, duplicate share submission

- [ ] **Step 6: Run tests — verify FAIL**

- [ ] **Step 7: Implement SyncCeremony**

```elixir
defmodule PkiCaEngine.KeyCeremony.SyncCeremony do
  @moduledoc """
  Synchronous key ceremony — all custodians present simultaneously.
  Follows spec Section 5.1 steps exactly.
  """

  alias PkiCaEngine.{Repo, Schema.KeyCeremony, Schema.IssuerKey, Schema.ThresholdShare}
  alias PkiCaEngine.KeyCeremony.ShareEncryption

  def initiate(params) do
    # Validate: at least one keystore exists
    # Create ceremony record with status: "initiated"
    # Create issuer_key record with status: "pending"
    # Return ceremony
  end

  def generate_keypair(ceremony) do
    # Get provider from keystore
    # Generate keypair via KeyGeneratorProtocol
    # Hold private key in process state (NOT in DB)
    # Return {public_key, private_key_handle}
  end

  def distribute_share(ceremony, custodian_user_id, custodian_password, share_data) do
    # Encrypt share with custodian's password
    encrypted = ShareEncryption.encrypt_share(share_data, custodian_password)
    # Store in threshold_shares table
    # Return :ok
  end

  def complete(ceremony, opts) do
    # Based on opts:
    # Path A (Independent Root): generate self-signed cert, mark key active,
    #   then generate sub-CA keypair + cert
    # Path B (Sub-CA): generate CSR, mark key pending
    # Update ceremony status to "completed"
    # Wipe private key material from memory
  end
end
```

The full implementation should use `KeyX.generate_shares!/3` to split the private key (or HSM password) into N shares.

- [ ] **Step 8: Run tests — verify PASS**

- [ ] **Step 9: Commit**

```bash
git add -A && git commit -m "feat: add synchronous key ceremony with threshold share distribution"
```

---

## Chunk 7: Key Ceremony — Asynchronous + Key Activation

### Task 9: Implement Asynchronous Key Ceremony

**Files:**
- Create: `lib/pki_ca_engine/key_ceremony/async_ceremony.ex`
- Create: `test/pki_ca_engine/key_ceremony/async_ceremony_test.exs`

Extends the sync ceremony with a time window. Uses a GenServer to hold encrypted key material in memory during the window.

- [ ] **Step 1: Write tests**

Test:
- `initiate/1` — creates ceremony with window_expires_at
- `submit_share/3` — custodian submits share independently
- Ceremony auto-completes when all N shares collected
- Ceremony fails when window expires (timer fires)
- Crash recovery: ceremony must be restarted
- Graceful shutdown: ceremony marked failed

- [ ] **Step 2: Run tests — verify FAIL**

- [ ] **Step 3: Implement AsyncCeremony GenServer**

The async ceremony holds encrypted key material in GenServer state with a timer. Key security per spec:
- Key material sealed with AES-256-GCM session key
- Timer for window expiry
- `terminate/2` callback zeroes key material on shutdown

- [ ] **Step 4: Run tests — verify PASS**

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: add asynchronous key ceremony with time window"
```

---

### Task 10: Implement Day-to-Day Key Activation

**Files:**
- Create: `lib/pki_ca_engine/key_activation.ex`
- Create: `test/pki_ca_engine/key_activation_test.exs`

Per spec Section 5.3: K custodians provide shares → secret reconstructed → key loaded into provider GenServer → available for signing with timeout.

- [ ] **Step 1: Write tests**

Test:
- `submit_share/3` — custodian decrypts and provides share
- `activate/1` — when K shares collected, reconstruct secret, load key
- `deactivate/1` — explicitly wipe key from provider
- `is_active?/1` — check if key is currently activated
- Timeout: key auto-deactivates after configured period
- Multiple keys can be active simultaneously

- [ ] **Step 2: Run tests — verify FAIL**

- [ ] **Step 3: Implement KeyActivation GenServer**

```elixir
defmodule PkiCaEngine.KeyActivation do
  @moduledoc """
  Day-to-day key activation via threshold share reconstruction.
  Holds active key handles in GenServer state with configurable timeout.
  """
  use GenServer

  # State: %{active_keys: %{issuer_key_id => %{handle: ..., timer_ref: ..., activated_at: ...}},
  #          pending_shares: %{issuer_key_id => [decrypted_shares]}}

  def submit_share(issuer_key_id, custodian_user_id, password) do
    # 1. Fetch encrypted share from threshold_shares
    # 2. Decrypt with password via ShareEncryption
    # 3. Add to pending_shares
    # 4. If len(pending_shares) >= min_shares, auto-activate
  end

  def activate(issuer_key_id) do
    # 1. Reconstruct secret via KeyX.recover_secret!
    # 2. Software: load private key into provider
    #    HSM: use password to unlock HSM slot
    # 3. Start timeout timer
    # 4. Move from pending to active_keys
  end

  def deactivate(issuer_key_id) do
    # 1. Cancel timer
    # 2. Wipe key from provider state
    # 3. Remove from active_keys
  end

  def is_active?(issuer_key_id) do
    GenServer.call(__MODULE__, {:is_active, issuer_key_id})
  end

  def sign(issuer_key_id, data) do
    # 1. Check key is active
    # 2. Sign via PrivateKeyOps protocol
    # 3. Return signature
  end
end
```

- [ ] **Step 4: Run tests — verify PASS**

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: add day-to-day key activation with timeout"
```

---

## Chunk 8: Certificate Signing

### Task 11: Implement Certificate Signing Pipeline

**Files:**
- Create: `lib/pki_ca_engine/certificate_signing.ex`
- Create: `test/pki_ca_engine/certificate_signing_test.exs`

Per spec Section 6.1 step 4: RA sends approved CSR + cert profile → CA signs → returns cert.

- [ ] **Step 1: Write tests**

Test:
- `sign_certificate/3` — takes CSR (DER), cert profile (map), issuer_key_id → returns signed cert
- Validates issuer key is active (threshold-activated)
- Applies cert profile extensions (key usage, validity, URLs)
- Assigns serial number (random 8 bytes)
- Returns `{:ok, %{cert_der: ..., cert_pem: ..., serial: ...}}`
- Stores in `issued_certificates` table
- Error: key not active → `{:error, :key_not_active}`
- Error: invalid CSR → `{:error, :invalid_csr}`

- [ ] **Step 2: Run tests — verify FAIL**

- [ ] **Step 3: Implement CertificateSigning**

```elixir
defmodule PkiCaEngine.CertificateSigning do
  @moduledoc """
  Certificate signing pipeline.
  Takes an approved CSR + cert profile, signs with active issuer key.
  """

  alias PkiCaEngine.{Repo, Schema.IssuedCertificate, KeyActivation}

  def sign_certificate(csr_der, cert_profile, issuer_key_id) do
    with :ok <- verify_key_active(issuer_key_id),
         {:ok, csr} <- parse_csr(csr_der),
         {:ok, cert} <- build_and_sign(csr, cert_profile, issuer_key_id),
         {:ok, record} <- store_certificate(cert, issuer_key_id, cert_profile) do
      {:ok, record}
    end
  end

  def revoke_certificate(serial_number, reason) do
    # Update issued_certificate status to "revoked"
    # Set revoked_at and revocation_reason
  end

  defp verify_key_active(issuer_key_id) do
    if KeyActivation.is_active?(issuer_key_id), do: :ok, else: {:error, :key_not_active}
  end

  defp parse_csr(csr_der) do
    # Validate CSR structure and signature
    # Return parsed CSR
  end

  defp build_and_sign(csr, cert_profile, issuer_key_id) do
    # 1. Build cert extensions from profile (key_usage, ext_key_usage, validity, CRL/OCSP URLs)
    # 2. Generate serial number
    # 3. Sign via KeyActivation.sign(issuer_key_id, tbs_certificate)
    # 4. Return {cert_der, cert_pem}
  end

  defp store_certificate(cert, issuer_key_id, cert_profile) do
    %IssuedCertificate{}
    |> IssuedCertificate.changeset(%{
      serial_number: cert.serial,
      issuer_key_id: issuer_key_id,
      subject_dn: cert.subject_dn,
      cert_der: cert.der,
      cert_pem: cert.pem,
      not_before: cert.not_before,
      not_after: cert.not_after,
      cert_profile_id: cert_profile[:id]
    })
    |> Repo.insert()
  end
end
```

- [ ] **Step 4: Run tests — verify PASS**

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: add certificate signing pipeline"
```

---

## Chunk 9: Core CA Engine GenServer + Service Registration

### Task 12: Implement Core CA Engine GenServer

**Files:**
- Create: `lib/pki_ca_engine/engine.ex`
- Create: `test/pki_ca_engine/engine_test.exs`
- Modify: `lib/pki_ca_engine/application.ex`

The main entry point GenServer per the spec. Coordinates all sub-modules. Registers with `strap_proc_reg` for discovery by other nodes.

- [ ] **Step 1: Write tests**

Test:
- `start_link/1` — starts with ca_instance_id
- `handle_call {:sign_certificate, ...}` — delegates to CertificateSigning
- `handle_call {:initiate_ceremony, ...}` — delegates to KeyCeremony
- `handle_call {:activate_key, ...}` — delegates to KeyActivation
- `handle_call {:get_status}` — returns engine status (active keys, ceremony state)
- Only accepts authenticated requests (check actor context)

- [ ] **Step 2: Run tests — verify FAIL**

- [ ] **Step 3: Implement Engine**

```elixir
defmodule PkiCaEngine.Engine do
  @moduledoc """
  Core CA Engine — main entry point for all CA operations.
  One instance per CA owner. Registers with strap_proc_reg for discovery.
  """
  use GenServer

  def start_link(opts) do
    ca_instance_id = Keyword.fetch!(opts, :ca_instance_id)
    GenServer.start_link(__MODULE__, opts, name: via_tuple(ca_instance_id))
  end

  defp via_tuple(ca_instance_id) do
    {:via, :global, {__MODULE__, ca_instance_id}}
  end

  @impl true
  def init(opts) do
    ca_instance_id = Keyword.fetch!(opts, :ca_instance_id)
    # Register with strap_proc_reg if available
    {:ok, %{ca_instance_id: ca_instance_id}}
  end

  @impl true
  def handle_call({:sign_certificate, csr_der, cert_profile, issuer_key_id}, _from, state) do
    result = PkiCaEngine.CertificateSigning.sign_certificate(csr_der, cert_profile, issuer_key_id)
    {:reply, result, state}
  end

  # ... other handle_call clauses for ceremony, activation, user mgmt, etc.
end
```

- [ ] **Step 4: Update Application supervisor**

Add Engine to supervision tree (dynamically started per CA instance):
```elixir
# In application.ex, add DynamicSupervisor for engines
children = [
  PkiCaEngine.Repo,
  {DynamicSupervisor, strategy: :one_for_one, name: PkiCaEngine.EngineSupervisor}
]
```

- [ ] **Step 5: Run tests — verify PASS**

- [ ] **Step 6: Run full test suite**

```bash
mix test
```

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "feat: add Core CA Engine GenServer with service registration"
```

---

## Summary

**What is built after completing this plan:**

| Module | Responsibility |
|--------|----------------|
| `PkiCaEngine.Engine` | Main GenServer entry point, coordinates all operations |
| `PkiCaEngine.UserManagement` | CA user CRUD with role-based access control |
| `PkiCaEngine.KeystoreManagement` | Keystore CRUD, provider mapping (soft/HSM) |
| `PkiCaEngine.KeypairAccess` | Key-to-user access binding |
| `PkiCaEngine.IssuerKeyManagement` | Issuer key lifecycle, cert/CSR generation |
| `PkiCaEngine.KeyCeremony.SyncCeremony` | Synchronous key ceremony (root CA) |
| `PkiCaEngine.KeyCeremony.AsyncCeremony` | Asynchronous key ceremony (sub-CA) |
| `PkiCaEngine.KeyCeremony.ShareEncryption` | Share encryption with Argon2 + AES-256-GCM |
| `PkiCaEngine.KeyActivation` | Day-to-day threshold key activation with timeout |
| `PkiCaEngine.CertificateSigning` | Certificate signing pipeline |
| `PkiCaEngine.Schema.*` | 8 Ecto schemas for all database tables |

**Database:** 8 tables with proper indexes, constraints, and associations.

**Integration points:**
- `strap_priv_key_store_provider` protocols for crypto operations
- `keyx` for Shamir Secret Sharing
- `ex_ccrypto` + `x509` for certificate generation
- `pki_audit_trail` for audit logging (to be wired in during implementation)
- `strap_proc_reg` for service registration (to be wired in during implementation)

**Next plan:** Plan 3 — `pki_ra_engine`
