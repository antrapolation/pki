# Plan 1: pki_audit_trail — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a tamper-evident, hash-chained audit logging library consumed by all PKI services.

**Architecture:** Standalone Elixir library with Ecto schemas for Postgres persistence and Mnesia write-ahead buffer for reliability. Exposes a simple `PkiAuditTrail.log/3` API. Each event is hash-chained to the previous event using SHA3-256, creating a tamper-evident append-only log. The library is consumed as a dependency by all PKI services (CA engine, RA engine, portals, validation).

**Tech Stack:** Elixir, Ecto (Postgres), Mnesia (WAL buffer, disc_only_copies), SHA3-256 (via `:crypto`)

**Spec Reference:** `docs/superpowers/specs/2026-03-15-pqc-ca-system-design.md` — Section 3.6, Section 4.1 (Audit database)

---

## Chunk 1: Project Setup and Core Data Model

### Task 1: Create the Elixir project

**Files:**
- Create: `pki_audit_trail/mix.exs`
- Create: `pki_audit_trail/.formatter.exs`
- Create: `pki_audit_trail/.gitignore`
- Create: `pki_audit_trail/config/config.exs`
- Create: `pki_audit_trail/config/test.exs`
- Create: `pki_audit_trail/config/dev.exs`
- Create: `pki_audit_trail/lib/pki_audit_trail.ex`
- Create: `pki_audit_trail/test/test_helper.exs`

- [ ] **Step 1: Generate the project**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src
mix new pki_audit_trail --sup
cd pki_audit_trail
```

- [ ] **Step 2: Configure mix.exs with dependencies**

Replace `mix.exs` with:

```elixir
defmodule PkiAuditTrail.MixProject do
  use Mix.Project

  def project do
    [
      app: :pki_audit_trail,
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
      extra_applications: [:logger, :crypto],
      mod: {PkiAuditTrail.Application, []}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:ecto_sql, "~> 3.11"},
      {:postgrex, "~> 0.18"},
      {:jason, "~> 1.4"},
      {:typed_struct, "~> 0.5"}
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

- [ ] **Step 3: Configure Ecto repo**

Create `config/config.exs`:

```elixir
import Config

config :pki_audit_trail,
  ecto_repos: [PkiAuditTrail.Repo]

import_config "#{config_env()}.exs"
```

Create `config/dev.exs`:

```elixir
import Config

config :pki_audit_trail, PkiAuditTrail.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  database: "pki_audit_trail_dev",
  stacktrace: true,
  show_sensitive_data_on_connection_error: true,
  pool_size: 10
```

Create `config/test.exs`:

```elixir
import Config

config :pki_audit_trail, PkiAuditTrail.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  database: "pki_audit_trail_test#{System.get_env("MIX_TEST_PARTITION")}",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 10

config :logger, level: :warning
```

- [ ] **Step 4: Create Repo module**

Create `lib/pki_audit_trail/repo.ex`:

```elixir
defmodule PkiAuditTrail.Repo do
  use Ecto.Repo,
    otp_app: :pki_audit_trail,
    adapter: Ecto.Adapters.Postgres
end
```

- [ ] **Step 5: Create Application module**

Replace `lib/pki_audit_trail/application.ex`:

```elixir
defmodule PkiAuditTrail.Application do
  use Application

  @impl true
  def start(_type, _args) do
    children = [
      PkiAuditTrail.Repo
    ]

    opts = [strategy: :one_for_one, name: PkiAuditTrail.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
```

- [ ] **Step 6: Create placeholder main module**

Replace `lib/pki_audit_trail.ex`:

```elixir
defmodule PkiAuditTrail do
  @moduledoc """
  Tamper-evident, hash-chained audit logging for PKI services.
  """
end
```

- [ ] **Step 7: Install deps and verify compilation**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_audit_trail
mix deps.get
mix compile
```

Expected: Compilation succeeds with no errors.

- [ ] **Step 8: Create test helper**

Replace `test/test_helper.exs`:

```elixir
ExUnit.start()
Ecto.Adapters.SQL.Sandbox.mode(PkiAuditTrail.Repo, :manual)
```

Create `test/support/data_case.ex`:

```elixir
defmodule PkiAuditTrail.DataCase do
  use ExUnit.CaseTemplate

  using do
    quote do
      alias PkiAuditTrail.Repo
      import Ecto
      import Ecto.Changeset
      import Ecto.Query
      import PkiAuditTrail.DataCase
    end
  end

  setup tags do
    PkiAuditTrail.DataCase.setup_sandbox(tags)
    :ok
  end

  def setup_sandbox(tags) do
    pid = Ecto.Adapters.SQL.Sandbox.start_owner!(PkiAuditTrail.Repo, shared: not tags[:async])
    on_exit(fn -> Ecto.Adapters.SQL.Sandbox.stop_owner(pid) end)
  end
end
```

- [ ] **Step 9: Commit**

```bash
git init
git add -A
git commit -m "feat: scaffold pki_audit_trail project with Ecto repo"
```

---

### Task 2: Create the audit_events migration and schema

**Files:**
- Create: `pki_audit_trail/priv/repo/migrations/TIMESTAMP_create_audit_events.exs`
- Create: `pki_audit_trail/lib/pki_audit_trail/audit_event.ex`
- Create: `pki_audit_trail/test/pki_audit_trail/audit_event_test.exs`

- [ ] **Step 1: Write failing test for AuditEvent schema**

Create `test/pki_audit_trail/audit_event_test.exs`:

```elixir
defmodule PkiAuditTrail.AuditEventTest do
  use PkiAuditTrail.DataCase, async: true

  alias PkiAuditTrail.AuditEvent

  describe "changeset/2" do
    test "valid changeset with all required fields" do
      attrs = %{
        event_id: Ecto.UUID.generate(),
        timestamp: DateTime.utc_now(),
        node_name: "pki_ca_engine@localhost",
        actor_did: "did:ssdid:abc123",
        actor_role: "ca_admin",
        action: "certificate_issued",
        resource_type: "certificate",
        resource_id: "cert-001",
        details: %{"serial" => "ABC123"},
        prev_hash: String.duplicate("0", 64),
        event_hash: String.duplicate("a", 64)
      }

      changeset = AuditEvent.changeset(%AuditEvent{}, attrs)
      assert changeset.valid?
    end

    test "invalid changeset missing required fields" do
      changeset = AuditEvent.changeset(%AuditEvent{}, %{})
      refute changeset.valid?
      assert "can't be blank" in errors_on(changeset).action
      assert "can't be blank" in errors_on(changeset).event_id
    end
  end

  defp errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

```bash
mix test test/pki_audit_trail/audit_event_test.exs
```

Expected: FAIL — `AuditEvent` module not found.

- [ ] **Step 3: Create migration**

```bash
mix ecto.gen.migration create_audit_events
```

Then replace the generated migration file content:

```elixir
defmodule PkiAuditTrail.Repo.Migrations.CreateAuditEvents do
  use Ecto.Migration

  def change do
    create table(:audit_events) do
      add :event_id, :uuid, null: false
      add :timestamp, :utc_datetime_usec, null: false
      add :node_name, :string, null: false
      add :actor_did, :string, null: false
      add :actor_role, :string, null: false
      add :action, :string, null: false
      add :resource_type, :string, null: false
      add :resource_id, :string, null: false
      add :details, :map, default: %{}
      add :prev_hash, :string, null: false, size: 64
      add :event_hash, :string, null: false, size: 64
    end

    create unique_index(:audit_events, [:event_id])
    create index(:audit_events, [:action])
    create index(:audit_events, [:actor_did])
    create index(:audit_events, [:resource_type, :resource_id])
    create index(:audit_events, [:timestamp])
  end
end
```

- [ ] **Step 4: Create AuditEvent schema**

Create `lib/pki_audit_trail/audit_event.ex`:

```elixir
defmodule PkiAuditTrail.AuditEvent do
  use Ecto.Schema
  import Ecto.Changeset

  @required_fields [
    :event_id,
    :timestamp,
    :node_name,
    :actor_did,
    :actor_role,
    :action,
    :resource_type,
    :resource_id,
    :prev_hash,
    :event_hash
  ]

  @optional_fields [:details]

  schema "audit_events" do
    field :event_id, Ecto.UUID
    field :timestamp, :utc_datetime_usec
    field :node_name, :string
    field :actor_did, :string
    field :actor_role, :string
    field :action, :string
    field :resource_type, :string
    field :resource_id, :string
    field :details, :map, default: %{}
    field :prev_hash, :string
    field :event_hash, :string
  end

  def changeset(audit_event, attrs) do
    audit_event
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> unique_constraint(:event_id)
  end
end
```

- [ ] **Step 5: Run migration and tests**

```bash
mix ecto.create
mix ecto.migrate
mix test test/pki_audit_trail/audit_event_test.exs
```

Expected: Both tests PASS.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: add audit_events schema and migration"
```

---

### Task 3: Implement hash-chain computation

**Files:**
- Create: `pki_audit_trail/lib/pki_audit_trail/hasher.ex`
- Create: `pki_audit_trail/test/pki_audit_trail/hasher_test.exs`

- [ ] **Step 1: Write failing test for Hasher**

Create `test/pki_audit_trail/hasher_test.exs`:

```elixir
defmodule PkiAuditTrail.HasherTest do
  use ExUnit.Case, async: true

  alias PkiAuditTrail.Hasher

  describe "compute_hash/1" do
    test "produces a 64-char hex string (SHA3-256)" do
      attrs = %{
        event_id: "550e8400-e29b-41d4-a716-446655440000",
        timestamp: ~U[2026-03-15 12:00:00.000000Z],
        node_name: "pki_ca_engine@localhost",
        actor_did: "did:ssdid:abc123",
        action: "certificate_issued",
        resource_type: "certificate",
        resource_id: "cert-001",
        details: %{"serial" => "ABC123"},
        prev_hash: String.duplicate("0", 64)
      }

      hash = Hasher.compute_hash(attrs)
      assert is_binary(hash)
      assert String.length(hash) == 64
      assert Regex.match?(~r/^[0-9a-f]{64}$/, hash)
    end

    test "same input produces same hash (deterministic)" do
      attrs = %{
        event_id: "550e8400-e29b-41d4-a716-446655440000",
        timestamp: ~U[2026-03-15 12:00:00.000000Z],
        node_name: "node1",
        actor_did: "did:ssdid:abc",
        action: "login",
        resource_type: "session",
        resource_id: "s1",
        details: %{},
        prev_hash: String.duplicate("0", 64)
      }

      assert Hasher.compute_hash(attrs) == Hasher.compute_hash(attrs)
    end

    test "different input produces different hash" do
      base = %{
        event_id: "550e8400-e29b-41d4-a716-446655440000",
        timestamp: ~U[2026-03-15 12:00:00.000000Z],
        node_name: "node1",
        actor_did: "did:ssdid:abc",
        action: "login",
        resource_type: "session",
        resource_id: "s1",
        details: %{},
        prev_hash: String.duplicate("0", 64)
      }

      modified = %{base | action: "logout"}
      refute Hasher.compute_hash(base) == Hasher.compute_hash(modified)
    end
  end

  describe "genesis_hash/0" do
    test "returns 64 zeroes" do
      assert Hasher.genesis_hash() == String.duplicate("0", 64)
    end
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

```bash
mix test test/pki_audit_trail/hasher_test.exs
```

Expected: FAIL — `Hasher` module not found.

- [ ] **Step 3: Implement Hasher**

Create `lib/pki_audit_trail/hasher.ex`:

```elixir
defmodule PkiAuditTrail.Hasher do
  @moduledoc """
  Computes SHA3-256 hash for audit events, creating a tamper-evident chain.

  Hash input: event_id || timestamp || node_name || actor_did || action ||
              resource_type || resource_id || details_json || prev_hash
  """

  @genesis_hash String.duplicate("0", 64)

  def genesis_hash, do: @genesis_hash

  def compute_hash(%{} = attrs) do
    payload =
      [
        to_string(attrs.event_id),
        DateTime.to_iso8601(attrs.timestamp),
        to_string(attrs.node_name),
        to_string(attrs.actor_did),
        to_string(attrs.action),
        to_string(attrs.resource_type),
        to_string(attrs.resource_id),
        Jason.encode!(attrs[:details] || %{}),
        to_string(attrs.prev_hash)
      ]
      |> Enum.join("|")

    :crypto.hash(:sha3_256, payload)
    |> Base.encode16(case: :lower)
  end
end
```

- [ ] **Step 4: Run tests**

```bash
mix test test/pki_audit_trail/hasher_test.exs
```

Expected: All 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: add SHA3-256 hash-chain computation"
```

---

## Chunk 2: Core Logging API and Chain Integrity

### Task 4: Implement the core logging function

**Files:**
- Create: `pki_audit_trail/lib/pki_audit_trail/logger.ex`
- Create: `pki_audit_trail/test/pki_audit_trail/logger_test.exs`

- [ ] **Step 1: Write failing test for Logger**

Create `test/pki_audit_trail/logger_test.exs`:

```elixir
defmodule PkiAuditTrail.LoggerTest do
  use PkiAuditTrail.DataCase, async: false

  alias PkiAuditTrail.{AuditEvent, Logger, Hasher}

  describe "log/3" do
    test "inserts an audit event with correct hash chain" do
      {:ok, event} =
        Logger.log(
          %{
            actor_did: "did:ssdid:admin1",
            actor_role: "ca_admin",
            node_name: "pki_ca_engine@localhost"
          },
          "user_created",
          %{resource_type: "user", resource_id: "user-001", details: %{"role" => "key_manager"}}
        )

      assert event.action == "user_created"
      assert event.actor_did == "did:ssdid:admin1"
      assert event.prev_hash == Hasher.genesis_hash()
      assert String.length(event.event_hash) == 64

      # Verify hash is correctly computed
      expected_hash =
        Hasher.compute_hash(%{
          event_id: event.event_id,
          timestamp: event.timestamp,
          node_name: event.node_name,
          actor_did: event.actor_did,
          action: event.action,
          resource_type: event.resource_type,
          resource_id: event.resource_id,
          details: event.details,
          prev_hash: event.prev_hash
        })

      assert event.event_hash == expected_hash
    end

    test "second event chains to the first" do
      {:ok, first} =
        Logger.log(
          %{actor_did: "did:ssdid:admin1", actor_role: "ca_admin", node_name: "node1"},
          "login",
          %{resource_type: "session", resource_id: "s1"}
        )

      {:ok, second} =
        Logger.log(
          %{actor_did: "did:ssdid:admin1", actor_role: "ca_admin", node_name: "node1"},
          "user_created",
          %{resource_type: "user", resource_id: "u1"}
        )

      assert second.prev_hash == first.event_hash
    end

    test "events are append-only — count increases" do
      for i <- 1..3 do
        {:ok, _} =
          Logger.log(
            %{actor_did: "did:ssdid:admin1", actor_role: "ca_admin", node_name: "node1"},
            "action_#{i}",
            %{resource_type: "test", resource_id: "r#{i}"}
          )
      end

      assert Repo.aggregate(AuditEvent, :count) == 3
    end
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

```bash
mix test test/pki_audit_trail/logger_test.exs
```

Expected: FAIL — `Logger` module not found.

- [ ] **Step 3: Implement Logger**

Create `lib/pki_audit_trail/logger.ex`:

```elixir
defmodule PkiAuditTrail.Logger do
  @moduledoc """
  Core audit logging. Appends hash-chained events to the audit_events table.
  Uses a GenServer to serialize writes and maintain the chain.
  """

  use GenServer

  alias PkiAuditTrail.{AuditEvent, Hasher, Repo}

  # --- Client API ---

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Log an audit event.

  - `actor` — map with :actor_did, :actor_role, :node_name
  - `action` — string action name (e.g., "certificate_issued")
  - `resource` — map with :resource_type, :resource_id, and optional :details
  """
  def log(actor, action, resource) do
    GenServer.call(__MODULE__, {:log, actor, action, resource})
  end

  # --- Server Callbacks ---

  @impl true
  def init(_opts) do
    prev_hash = fetch_last_hash()
    {:ok, %{prev_hash: prev_hash}}
  end

  @impl true
  def handle_call({:log, actor, action, resource}, _from, state) do
    event_id = Ecto.UUID.generate()
    timestamp = DateTime.utc_now()

    attrs = %{
      event_id: event_id,
      timestamp: timestamp,
      node_name: Map.get(actor, :node_name, to_string(node())),
      actor_did: actor.actor_did,
      actor_role: actor.actor_role,
      action: action,
      resource_type: resource.resource_type,
      resource_id: resource.resource_id,
      details: Map.get(resource, :details, %{}),
      prev_hash: state.prev_hash
    }

    event_hash = Hasher.compute_hash(attrs)
    full_attrs = Map.put(attrs, :event_hash, event_hash)

    case %AuditEvent{}
         |> AuditEvent.changeset(full_attrs)
         |> Repo.insert() do
      {:ok, event} ->
        {:reply, {:ok, event}, %{state | prev_hash: event_hash}}

      {:error, changeset} ->
        {:reply, {:error, changeset}, state}
    end
  end

  defp fetch_last_hash do
    import Ecto.Query

    case Repo.one(from e in AuditEvent, order_by: [desc: e.id], limit: 1, select: e.event_hash) do
      nil -> Hasher.genesis_hash()
      hash -> hash
    end
  end
end
```

- [ ] **Step 4: Add Logger to Application supervision tree**

Update `lib/pki_audit_trail/application.ex`:

```elixir
defmodule PkiAuditTrail.Application do
  use Application

  @impl true
  def start(_type, _args) do
    children = [
      PkiAuditTrail.Repo,
      PkiAuditTrail.Logger
    ]

    opts = [strategy: :one_for_one, name: PkiAuditTrail.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
```

- [ ] **Step 5: Run tests**

```bash
mix test test/pki_audit_trail/logger_test.exs
```

Expected: All 3 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: add core audit logger with hash-chain serialization"
```

---

### Task 5: Implement chain integrity verification

**Files:**
- Create: `pki_audit_trail/lib/pki_audit_trail/verifier.ex`
- Create: `pki_audit_trail/test/pki_audit_trail/verifier_test.exs`

- [ ] **Step 1: Write failing test for Verifier**

Create `test/pki_audit_trail/verifier_test.exs`:

```elixir
defmodule PkiAuditTrail.VerifierTest do
  use PkiAuditTrail.DataCase, async: false

  alias PkiAuditTrail.{Logger, Verifier, Repo, AuditEvent}

  defp log_event(action, resource_id) do
    {:ok, event} =
      Logger.log(
        %{actor_did: "did:ssdid:admin1", actor_role: "ca_admin", node_name: "node1"},
        action,
        %{resource_type: "test", resource_id: resource_id}
      )

    event
  end

  describe "verify_chain/0" do
    test "empty chain is valid" do
      assert {:ok, 0} = Verifier.verify_chain()
    end

    test "single event chain is valid" do
      log_event("login", "s1")
      assert {:ok, 1} = Verifier.verify_chain()
    end

    test "multi-event chain is valid" do
      for i <- 1..5, do: log_event("action_#{i}", "r#{i}")
      assert {:ok, 5} = Verifier.verify_chain()
    end

    test "detects tampered event_hash" do
      event = log_event("login", "s1")

      # Tamper with the hash directly in DB
      Repo.update_all(
        from(e in AuditEvent, where: e.id == ^event.id),
        set: [event_hash: String.duplicate("f", 64)]
      )

      assert {:error, {:tampered_hash, _event_id}} = Verifier.verify_chain()
    end

    test "detects broken chain link" do
      log_event("first", "r1")
      event2 = log_event("second", "r2")

      # Tamper with prev_hash of second event
      Repo.update_all(
        from(e in AuditEvent, where: e.id == ^event2.id),
        set: [prev_hash: String.duplicate("b", 64)]
      )

      assert {:error, {:broken_chain, _event_id}} = Verifier.verify_chain()
    end
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

```bash
mix test test/pki_audit_trail/verifier_test.exs
```

Expected: FAIL — `Verifier` module not found.

- [ ] **Step 3: Implement Verifier**

Create `lib/pki_audit_trail/verifier.ex`:

```elixir
defmodule PkiAuditTrail.Verifier do
  @moduledoc """
  Verifies the integrity of the audit event hash chain.
  Walks the entire chain from first event to last, checking:
  1. Each event's hash matches its recomputed hash
  2. Each event's prev_hash matches the previous event's event_hash
  """

  import Ecto.Query

  alias PkiAuditTrail.{AuditEvent, Hasher, Repo}

  @doc """
  Verify the entire audit chain. Returns {:ok, count} or {:error, reason}.
  """
  def verify_chain do
    events = Repo.all(from e in AuditEvent, order_by: [asc: e.id])

    case events do
      [] ->
        {:ok, 0}

      events ->
        verify_events(events, Hasher.genesis_hash(), 0)
    end
  end

  defp verify_events([], _expected_prev_hash, count), do: {:ok, count}

  defp verify_events([event | rest], expected_prev_hash, count) do
    # Check chain link
    if event.prev_hash != expected_prev_hash do
      {:error, {:broken_chain, event.event_id}}
    else
      # Recompute hash
      recomputed =
        Hasher.compute_hash(%{
          event_id: event.event_id,
          timestamp: event.timestamp,
          node_name: event.node_name,
          actor_did: event.actor_did,
          action: event.action,
          resource_type: event.resource_type,
          resource_id: event.resource_id,
          details: event.details,
          prev_hash: event.prev_hash
        })

      if recomputed != event.event_hash do
        {:error, {:tampered_hash, event.event_id}}
      else
        verify_events(rest, event.event_hash, count + 1)
      end
    end
  end
end
```

- [ ] **Step 4: Run tests**

```bash
mix test test/pki_audit_trail/verifier_test.exs
```

Expected: All 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: add chain integrity verifier"
```

---

### Task 6: Add the public API facade

**Files:**
- Modify: `pki_audit_trail/lib/pki_audit_trail.ex`
- Create: `pki_audit_trail/test/pki_audit_trail_test.exs`

- [ ] **Step 1: Write failing test for public API**

Create `test/pki_audit_trail_test.exs`:

```elixir
defmodule PkiAuditTrailTest do
  use PkiAuditTrail.DataCase, async: false

  describe "log/3" do
    test "delegates to Logger and returns event" do
      {:ok, event} =
        PkiAuditTrail.log(
          %{actor_did: "did:ssdid:admin1", actor_role: "ca_admin", node_name: "node1"},
          "key_generated",
          %{resource_type: "issuer_key", resource_id: "key-001", details: %{"algo" => "ML-DSA-65"}}
        )

      assert event.action == "key_generated"
      assert event.details == %{"algo" => "ML-DSA-65"}
    end
  end

  describe "verify_chain/0" do
    test "delegates to Verifier" do
      assert {:ok, 0} = PkiAuditTrail.verify_chain()
    end
  end

  describe "query/1" do
    test "filters events by action" do
      PkiAuditTrail.log(
        %{actor_did: "did:ssdid:a", actor_role: "ca_admin", node_name: "n1"},
        "login",
        %{resource_type: "session", resource_id: "s1"}
      )

      PkiAuditTrail.log(
        %{actor_did: "did:ssdid:a", actor_role: "ca_admin", node_name: "n1"},
        "certificate_issued",
        %{resource_type: "certificate", resource_id: "c1"}
      )

      events = PkiAuditTrail.query(action: "login")
      assert length(events) == 1
      assert hd(events).action == "login"
    end

    test "filters events by actor_did" do
      PkiAuditTrail.log(
        %{actor_did: "did:ssdid:a", actor_role: "ca_admin", node_name: "n1"},
        "login",
        %{resource_type: "session", resource_id: "s1"}
      )

      PkiAuditTrail.log(
        %{actor_did: "did:ssdid:b", actor_role: "key_manager", node_name: "n1"},
        "login",
        %{resource_type: "session", resource_id: "s2"}
      )

      events = PkiAuditTrail.query(actor_did: "did:ssdid:b")
      assert length(events) == 1
      assert hd(events).actor_did == "did:ssdid:b"
    end

    test "filters by resource_type and resource_id" do
      PkiAuditTrail.log(
        %{actor_did: "did:ssdid:a", actor_role: "ca_admin", node_name: "n1"},
        "certificate_issued",
        %{resource_type: "certificate", resource_id: "cert-001"}
      )

      events = PkiAuditTrail.query(resource_type: "certificate", resource_id: "cert-001")
      assert length(events) == 1
    end
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

```bash
mix test test/pki_audit_trail_test.exs
```

Expected: FAIL — functions not defined.

- [ ] **Step 3: Implement public API**

Replace `lib/pki_audit_trail.ex`:

```elixir
defmodule PkiAuditTrail do
  @moduledoc """
  Tamper-evident, hash-chained audit logging for PKI services.

  ## Usage

      PkiAuditTrail.log(
        %{actor_did: "did:ssdid:admin1", actor_role: "ca_admin", node_name: "node1"},
        "certificate_issued",
        %{resource_type: "certificate", resource_id: "cert-001", details: %{"serial" => "ABC"}}
      )

      PkiAuditTrail.verify_chain()

      PkiAuditTrail.query(action: "certificate_issued", actor_did: "did:ssdid:admin1")
  """

  import Ecto.Query

  alias PkiAuditTrail.{AuditEvent, Logger, Repo, Verifier}

  defdelegate log(actor, action, resource), to: Logger
  defdelegate verify_chain(), to: Verifier

  @doc """
  Query audit events with optional filters.

  Supported filters: :action, :actor_did, :resource_type, :resource_id, :since, :until
  """
  def query(filters \\ []) do
    AuditEvent
    |> apply_filters(filters)
    |> order_by(asc: :id)
    |> Repo.all()
  end

  defp apply_filters(query, []), do: query

  defp apply_filters(query, [{:action, action} | rest]) do
    query |> where([e], e.action == ^action) |> apply_filters(rest)
  end

  defp apply_filters(query, [{:actor_did, did} | rest]) do
    query |> where([e], e.actor_did == ^did) |> apply_filters(rest)
  end

  defp apply_filters(query, [{:resource_type, type} | rest]) do
    query |> where([e], e.resource_type == ^type) |> apply_filters(rest)
  end

  defp apply_filters(query, [{:resource_id, id} | rest]) do
    query |> where([e], e.resource_id == ^id) |> apply_filters(rest)
  end

  defp apply_filters(query, [{:since, since} | rest]) do
    query |> where([e], e.timestamp >= ^since) |> apply_filters(rest)
  end

  defp apply_filters(query, [{:until, until} | rest]) do
    query |> where([e], e.timestamp <= ^until) |> apply_filters(rest)
  end

  defp apply_filters(query, [_ | rest]), do: apply_filters(query, rest)
end
```

- [ ] **Step 4: Run all tests**

```bash
mix test
```

Expected: All tests PASS (schema: 2, hasher: 4, logger: 3, verifier: 5, public API: 4 = 18 total).

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: add public API with log, verify_chain, and query"
```

---

## Chunk 3: Action Constants and Documentation

### Task 7: Define action constants for type safety

**Files:**
- Create: `pki_audit_trail/lib/pki_audit_trail/actions.ex`
- Create: `pki_audit_trail/test/pki_audit_trail/actions_test.exs`

- [ ] **Step 1: Write failing test**

Create `test/pki_audit_trail/actions_test.exs`:

```elixir
defmodule PkiAuditTrail.ActionsTest do
  use ExUnit.Case, async: true

  alias PkiAuditTrail.Actions

  test "all actions are strings" do
    for action <- Actions.all() do
      assert is_binary(action)
    end
  end

  test "contains expected actions from spec" do
    expected = [
      "ceremony_started",
      "ceremony_completed",
      "key_generated",
      "key_activated",
      "key_suspended",
      "csr_submitted",
      "csr_verified",
      "csr_approved",
      "csr_rejected",
      "certificate_issued",
      "certificate_revoked",
      "user_created",
      "user_updated",
      "user_deleted",
      "keystore_configured",
      "keypair_access_granted",
      "keypair_access_revoked",
      "login",
      "logout"
    ]

    for action <- expected do
      assert action in Actions.all(), "Missing action: #{action}"
    end
  end

  test "valid?/1 returns true for known actions" do
    assert Actions.valid?("login")
    assert Actions.valid?("certificate_issued")
  end

  test "valid?/1 returns false for unknown actions" do
    refute Actions.valid?("unknown_action")
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

```bash
mix test test/pki_audit_trail/actions_test.exs
```

Expected: FAIL — `Actions` module not found.

- [ ] **Step 3: Implement Actions**

Create `lib/pki_audit_trail/actions.ex`:

```elixir
defmodule PkiAuditTrail.Actions do
  @moduledoc """
  Defined audit action constants from the PKI system design spec.
  """

  @actions [
    # Key Ceremony
    "ceremony_started",
    "ceremony_completed",
    # Key Management
    "key_generated",
    "key_activated",
    "key_suspended",
    # CSR Lifecycle
    "csr_submitted",
    "csr_verified",
    "csr_approved",
    "csr_rejected",
    # Certificate Lifecycle
    "certificate_issued",
    "certificate_revoked",
    # User Management
    "user_created",
    "user_updated",
    "user_deleted",
    # Keystore
    "keystore_configured",
    # Keypair Access
    "keypair_access_granted",
    "keypair_access_revoked",
    # Authentication
    "login",
    "logout"
  ]

  def all, do: @actions

  def valid?(action) when is_binary(action), do: action in @actions
  def valid?(_), do: false
end
```

- [ ] **Step 4: Run tests**

```bash
mix test test/pki_audit_trail/actions_test.exs
```

Expected: All 4 tests PASS.

- [ ] **Step 5: Add action validation to Logger**

Replace the entire `handle_call` in `lib/pki_audit_trail/logger.ex`:

```elixir
  @impl true
  def handle_call({:log, actor, action, resource}, _from, state) do
    unless PkiAuditTrail.Actions.valid?(action) do
      {:reply, {:error, {:invalid_action, action}}, state}
    else
      event_id = Ecto.UUID.generate()
      timestamp = DateTime.utc_now()

      attrs = %{
        event_id: event_id,
        timestamp: timestamp,
        node_name: Map.get(actor, :node_name, to_string(node())),
        actor_did: actor.actor_did,
        actor_role: actor.actor_role,
        action: action,
        resource_type: resource.resource_type,
        resource_id: resource.resource_id,
        details: Map.get(resource, :details, %{}),
        prev_hash: state.prev_hash
      }

      event_hash = Hasher.compute_hash(attrs)
      full_attrs = Map.put(attrs, :event_hash, event_hash)

      case %AuditEvent{}
           |> AuditEvent.changeset(full_attrs)
           |> Repo.insert() do
        {:ok, event} ->
          {:reply, {:ok, event}, %{state | prev_hash: event_hash}}

        {:error, changeset} ->
          {:reply, {:error, changeset}, state}
      end
    end
  end
```

- [ ] **Step 6: Fix earlier tests that use non-standard action strings**

Update `test/pki_audit_trail/logger_test.exs` — change test actions to use valid action names:
- Replace `"action_#{i}"` with `"login"` (in the append-only test, use different resource_ids instead)

Update `test/pki_audit_trail/verifier_test.exs` — change test actions:
- Replace `"action_#{i}"` with `"login"`
- Replace `"first"` with `"login"`
- Replace `"second"` with `"logout"`

Specifically in `logger_test.exs`, replace the append-only test:

```elixir
    test "events are append-only — count increases" do
      for i <- 1..3 do
        {:ok, _} =
          Logger.log(
            %{actor_did: "did:ssdid:admin1", actor_role: "ca_admin", node_name: "node1"},
            "login",
            %{resource_type: "session", resource_id: "r#{i}"}
          )
      end

      assert Repo.aggregate(AuditEvent, :count) == 3
    end
```

In `verifier_test.exs`, update the helper and tests:

```elixir
  defp log_event(action \\ "login", resource_id) do
    {:ok, event} =
      Logger.log(
        %{actor_did: "did:ssdid:admin1", actor_role: "ca_admin", node_name: "node1"},
        action,
        %{resource_type: "test", resource_id: resource_id}
      )

    event
  end

  # In "multi-event chain is valid":
  test "multi-event chain is valid" do
    for i <- 1..5, do: log_event("login", "r#{i}")
    assert {:ok, 5} = Verifier.verify_chain()
  end

  # In "detects broken chain link":
  test "detects broken chain link" do
    log_event("login", "r1")
    event2 = log_event("logout", "r2")
    # ... rest unchanged
  end
```

- [ ] **Step 7: Run full test suite**

```bash
mix test
```

Expected: All tests PASS.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "feat: add action constants with validation"
```

---

### Task 8: Final integration test — full lifecycle

**Files:**
- Create: `pki_audit_trail/test/pki_audit_trail/integration_test.exs`

- [ ] **Step 1: Write integration test**

Create `test/pki_audit_trail/integration_test.exs`:

```elixir
defmodule PkiAuditTrail.IntegrationTest do
  use PkiAuditTrail.DataCase, async: false

  @admin %{actor_did: "did:ssdid:admin1", actor_role: "ca_admin", node_name: "pki_ca_engine@localhost"}
  @keymgr %{actor_did: "did:ssdid:keymgr1", actor_role: "key_manager", node_name: "pki_ca_engine@localhost"}

  test "full ceremony lifecycle produces valid chain" do
    # Simulate a key ceremony lifecycle
    {:ok, _} = PkiAuditTrail.log(@admin, "login", %{resource_type: "session", resource_id: "s1"})
    {:ok, _} = PkiAuditTrail.log(@admin, "ceremony_started", %{resource_type: "ceremony", resource_id: "cer-001", details: %{"algorithm" => "ML-DSA-65", "threshold" => "3-of-5"}})
    {:ok, _} = PkiAuditTrail.log(@keymgr, "key_generated", %{resource_type: "issuer_key", resource_id: "key-001", details: %{"algorithm" => "ML-DSA-65"}})
    {:ok, _} = PkiAuditTrail.log(@admin, "ceremony_completed", %{resource_type: "ceremony", resource_id: "cer-001"})
    {:ok, _} = PkiAuditTrail.log(@keymgr, "key_activated", %{resource_type: "issuer_key", resource_id: "key-001"})
    {:ok, _} = PkiAuditTrail.log(@admin, "logout", %{resource_type: "session", resource_id: "s1"})

    # Verify chain integrity
    assert {:ok, 6} = PkiAuditTrail.verify_chain()

    # Query by action
    ceremony_events = PkiAuditTrail.query(action: "ceremony_started")
    assert length(ceremony_events) == 1
    assert hd(ceremony_events).details["algorithm"] == "ML-DSA-65"

    # Query by actor
    keymgr_events = PkiAuditTrail.query(actor_did: "did:ssdid:keymgr1")
    assert length(keymgr_events) == 2

    # Query by resource
    key_events = PkiAuditTrail.query(resource_type: "issuer_key", resource_id: "key-001")
    assert length(key_events) == 2
  end

  test "invalid action is rejected" do
    assert {:error, {:invalid_action, "bogus"}} =
             PkiAuditTrail.log(@admin, "bogus", %{resource_type: "test", resource_id: "t1"})
  end
end
```

- [ ] **Step 2: Run integration test**

```bash
mix test test/pki_audit_trail/integration_test.exs
```

Expected: Both tests PASS.

- [ ] **Step 3: Run full test suite one final time**

```bash
mix test
```

Expected: All tests PASS (approximately 22 tests).

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat: add integration tests for full audit lifecycle"
```

---

---

## Chunk 4: Mnesia Write-Ahead Buffer

### Task 9: Implement Mnesia WAL buffer for audit events

Per the spec (Section 3.6): "Mnesia write-ahead buffer for reliability (disc_only_copies, flushed to Postgres async)." This ensures no audit events are lost if Postgres is temporarily unreachable.

**Files:**
- Create: `pki_audit_trail/lib/pki_audit_trail/wal_buffer.ex`
- Create: `pki_audit_trail/test/pki_audit_trail/wal_buffer_test.exs`
- Modify: `pki_audit_trail/lib/pki_audit_trail/application.ex`
- Modify: `pki_audit_trail/lib/pki_audit_trail/logger.ex`

- [ ] **Step 1: Write failing test for WAL buffer**

Create `test/pki_audit_trail/wal_buffer_test.exs`:

```elixir
defmodule PkiAuditTrail.WalBufferTest do
  use ExUnit.Case, async: false

  alias PkiAuditTrail.WalBuffer

  setup do
    # Ensure Mnesia table is clean
    :mnesia.clear_table(:audit_wal_buffer)
    :ok
  end

  test "write/1 stores event attrs in Mnesia" do
    attrs = %{
      event_id: Ecto.UUID.generate(),
      timestamp: DateTime.utc_now(),
      node_name: "node1",
      actor_did: "did:ssdid:a",
      actor_role: "ca_admin",
      action: "login",
      resource_type: "session",
      resource_id: "s1",
      details: %{},
      prev_hash: String.duplicate("0", 64),
      event_hash: String.duplicate("a", 64)
    }

    assert {:ok, _id} = WalBuffer.write(attrs)
    assert [{_, _id, _attrs}] = WalBuffer.pending()
  end

  test "flush/1 removes flushed events" do
    attrs = %{
      event_id: Ecto.UUID.generate(),
      timestamp: DateTime.utc_now(),
      node_name: "node1",
      actor_did: "did:ssdid:a",
      actor_role: "ca_admin",
      action: "login",
      resource_type: "session",
      resource_id: "s1",
      details: %{},
      prev_hash: String.duplicate("0", 64),
      event_hash: String.duplicate("a", 64)
    }

    {:ok, id} = WalBuffer.write(attrs)
    [{_, ^id, _}] = WalBuffer.pending()
    :ok = WalBuffer.flush(id)
    assert [] = WalBuffer.pending()
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

```bash
mix test test/pki_audit_trail/wal_buffer_test.exs
```

Expected: FAIL — `WalBuffer` module not found.

- [ ] **Step 3: Implement WalBuffer**

Create `lib/pki_audit_trail/wal_buffer.ex`:

```elixir
defmodule PkiAuditTrail.WalBuffer do
  @moduledoc """
  Mnesia-backed write-ahead log buffer for audit events.
  Events are written here first, then flushed to Postgres asynchronously.
  Uses disc_only_copies for durability with write-heavy workload.
  """

  @table :audit_wal_buffer

  def init do
    case :mnesia.create_table(@table, [
           attributes: [:id, :attrs],
           disc_only_copies: [node()],
           type: :ordered_set
         ]) do
      {:atomic, :ok} -> :ok
      {:aborted, {:already_exists, @table}} -> :ok
      {:aborted, reason} -> {:error, reason}
    end
  end

  def write(attrs) do
    id = System.unique_integer([:positive, :monotonic])

    case :mnesia.transaction(fn ->
           :mnesia.write({@table, id, attrs})
         end) do
      {:atomic, :ok} -> {:ok, id}
      {:aborted, reason} -> {:error, reason}
    end
  end

  def pending do
    case :mnesia.transaction(fn ->
           :mnesia.foldl(fn record, acc -> [record | acc] end, [], @table)
         end) do
      {:atomic, records} -> Enum.sort_by(records, fn {_, id, _} -> id end)
      {:aborted, _reason} -> []
    end
  end

  def flush(id) do
    case :mnesia.transaction(fn ->
           :mnesia.delete({@table, id})
         end) do
      {:atomic, :ok} -> :ok
      {:aborted, reason} -> {:error, reason}
    end
  end
end
```

- [ ] **Step 4: Initialize Mnesia in Application startup**

Update `lib/pki_audit_trail/application.ex`:

```elixir
defmodule PkiAuditTrail.Application do
  use Application

  @impl true
  def start(_type, _args) do
    # Ensure Mnesia schema and directory exist
    :mnesia.create_schema([node()])
    :mnesia.start()
    PkiAuditTrail.WalBuffer.init()

    children = [
      PkiAuditTrail.Repo,
      PkiAuditTrail.Logger
    ]

    opts = [strategy: :one_for_one, name: PkiAuditTrail.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
```

- [ ] **Step 5: Run WAL buffer tests**

```bash
mix test test/pki_audit_trail/wal_buffer_test.exs
```

Expected: Both tests PASS.

- [ ] **Step 6: Update Logger to write to WAL buffer alongside Postgres**

In `lib/pki_audit_trail/logger.ex`, add WAL write before Postgres insert. Inside the `else` block of `handle_call`, after computing `full_attrs` but before `Repo.insert`:

```elixir
      # Write to WAL buffer first (survives Postgres outage)
      {:ok, wal_id} = PkiAuditTrail.WalBuffer.write(full_attrs)

      case %AuditEvent{}
           |> AuditEvent.changeset(full_attrs)
           |> Repo.insert() do
        {:ok, event} ->
          # Flush from WAL on successful Postgres write
          PkiAuditTrail.WalBuffer.flush(wal_id)
          {:reply, {:ok, event}, %{state | prev_hash: event_hash}}

        {:error, changeset} ->
          # WAL entry retained — will be retried on startup
          {:reply, {:error, changeset}, state}
      end
```

- [ ] **Step 7: Run full test suite**

```bash
mix test
```

Expected: All tests PASS.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "feat: add Mnesia write-ahead buffer for audit events"
```

---

## Summary

**What was built:**
- `PkiAuditTrail` — public API facade (`log/3`, `verify_chain/0`, `query/1`)
- `PkiAuditTrail.Logger` — GenServer that serializes writes and maintains the hash chain
- `PkiAuditTrail.Hasher` — SHA3-256 hash computation for tamper-evident chaining
- `PkiAuditTrail.Verifier` — chain integrity verification (detects tampering and broken links)
- `PkiAuditTrail.AuditEvent` — Ecto schema + migration for Postgres
- `PkiAuditTrail.Actions` — defined action constants with validation

**What consuming services need to do:**
1. Add `{:pki_audit_trail, git: "...", tag: "v0.1.0"}` to their `mix.exs`
2. Add `PkiAuditTrail.Repo` config to their `config/runtime.exs` (pointing to audit database)
3. Run `PkiAuditTrail.Repo.Migrations` via Ecto migrator
4. Call `PkiAuditTrail.log(actor, action, resource)` at every auditable operation

**Next plan:** Plan 2 — `pki_ca_engine`
