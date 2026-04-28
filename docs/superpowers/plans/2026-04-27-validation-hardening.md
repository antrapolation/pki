# Validation Service Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix three production gaps in pki_validation (RFC 6960 nonce, per-issuer CRL scoping, orphaned PostgreSQL cleanup) and update architecture docs to reflect one-BEAM-node-per-tenant.

**Architecture:** Each tenant BEAM runs CA engine, RA engine, and pki_validation in-process; all state is in local Mnesia. PostgreSQL is platform-only (tenant registry, platform users, platform audit trail). The old per-tenant `t_<hex>_validation` PostgreSQL tables are fully orphaned.

**Tech Stack:** Elixir/OTP, Phoenix, Mnesia (pki_mnesia Repo), ExUnit, Plug/Cowboy

**Spec:** `docs/superpowers/specs/2026-04-27-validation-hardening-design.md`

---

## File Map

**Modified:**
- `src/pki_validation/lib/pki_validation/ocsp/der_responder.ex` — add nonce param to 4 error `ResponseBuilder.build` calls
- `src/pki_validation/lib/pki_validation/crl_publisher.ex` — per-issuer generation loop, state map, renamed API
- `src/pki_validation/lib/pki_validation/api/router.ex` — update `/health` and `GET /crl` for new crls API
- `src/pki_validation/test/crl_publisher_test.exs` — update to per-issuer API + add scoping test
- `src/pki_platform_engine/lib/pki_platform_engine/provisioner.ex` — remove 3 validation migration lines
- `src/pki_platform_engine/lib/mix/tasks/pki.migrate_existing_tenants.ex` — remove 2 validation functions
- `src/pki_platform_engine/lib/pki_platform_engine/tenant_prefix.ex` — remove `validation_prefix/1`, update pattern
- `src/pki_validation/config/config.exs` — remove `ecto_repos` entry
- `README.md` — replace old multi-port architecture diagram
- `docs/PKI-System-Technical-Summary.md` — replace separated-process diagram
- `CLAUDE.md` — update Architecture section
- `deploy/DEPLOYMENT.md` — remove warning banner
- `TODOS.md` — close validation repo wiring item

**Deleted:**
- `src/pki_platform_engine/priv/tenant_validation_schema.sql`
- `src/pki_validation/priv/repo/migrations/20260316000001_create_certificate_status.exs`
- `src/pki_validation/priv/repo/migrations/20260326000001_switch_to_uuidv7.exs`
- `src/pki_validation/priv/repo/migrations/20260407000001_add_issuer_name_hash.exs`
- `src/pki_validation/priv/repo/migrations/20260407000002_create_signing_key_config.exs`
- `src/pki_validation/priv/repo/migrations/20260407000003_create_crl_metadata.exs`

**Created:**
- `src/pki_validation/test/pki_validation/ocsp/der_responder_test.exs` — nonce-on-error tests

---

## Task 1: RFC 6960 Nonce on Error Responses

**Files:**
- Modify: `src/pki_validation/lib/pki_validation/ocsp/der_responder.ex:47-57, 114-115`
- Create: `src/pki_validation/test/pki_validation/ocsp/der_responder_test.exs`

- [ ] **Step 1: Write failing tests**

Create `src/pki_validation/test/pki_validation/ocsp/der_responder_test.exs`:

```elixir
defmodule PkiValidation.Ocsp.DerResponderTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.TestHelper
  alias PkiCaEngine.KeyActivation
  alias PkiValidation.Ocsp.DerResponder

  setup do
    dir = TestHelper.setup_mnesia()
    on_exit(fn -> TestHelper.teardown_mnesia(dir) end)
    :ok
  end

  describe "nonce echoing on error responses" do
    test "unauthorized response (nil issuer_key_id) echoes request nonce" do
      nonce = :crypto.strong_rand_bytes(16)
      request = %{cert_ids: [], nonce: nonce}

      {:ok, der} = DerResponder.respond(request, issuer_key_id: nil)

      assert :binary.match(der, nonce) != :nomatch,
             "Expected nonce to appear in unauthorized response DER"
    end

    test "try_later response echoes request nonce" do
      nonce = :crypto.strong_rand_bytes(16)
      key_id = "test-key-#{System.unique_integer()}"
      request = %{cert_ids: [], nonce: nonce}

      ka_name = :"test_ka_nonce_#{System.unique_integer()}"
      {:ok, ka} = KeyActivation.start_link(name: ka_name)
      on_exit(fn -> if Process.alive?(ka), do: GenServer.stop(ka) end)

      # No key registered in KeyActivation → lease_status returns %{active: false} → :try_later
      {:ok, der} =
        DerResponder.respond(request,
          issuer_key_id: key_id,
          activation_server: ka_name
        )

      assert :binary.match(der, nonce) != :nomatch,
             "Expected nonce to appear in try_later response DER"
    end
  end
end
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd src/pki_validation && mix test test/pki_validation/ocsp/der_responder_test.exs --no-start 2>&1 | tail -20
```

Expected: 2 failures — nonce not found in DER (`:binary.match` returns `:nomatch`).

- [ ] **Step 3: Fix der_responder.ex — add nonce to all 4 error build calls**

In `src/pki_validation/lib/pki_validation/ocsp/der_responder.ex`:

Change lines 47-57 (the `respond/2` error branches and rescue/catch):

```elixir
  def respond(%{cert_ids: cert_ids, nonce: nonce} = _request, opts) do
    activation_server = Keyword.get(opts, :activation_server, KeyActivation)
    issuer_key_id = Keyword.get(opts, :issuer_key_id)

    try do
      case resolve_signing_key(issuer_key_id, activation_server, cert_ids, nonce) do
        {:ok, der} ->
          {:ok, der}

        :try_later ->
          ResponseBuilder.build(:tryLater, [], dummy_key(), nonce: nonce)

        :unauthorized ->
          ResponseBuilder.build(:unauthorized, [], dummy_key(), nonce: nonce)
      end
    rescue
      _ -> ResponseBuilder.build(:internalError, [], dummy_key(), nonce: nonce)
    catch
      _, _ -> ResponseBuilder.build(:internalError, [], dummy_key(), nonce: nonce)
    end
  end
```

Change line 114-115 (the `build_signed_response/4` internal error branch):

```elixir
      {:error, _reason} ->
        ResponseBuilder.build(:internalError, [], dummy_key(), nonce: nonce)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd src/pki_validation && mix test test/pki_validation/ocsp/der_responder_test.exs --no-start 2>&1 | tail -10
```

Expected: `2 tests, 0 failures`

- [ ] **Step 5: Run full pki_validation suite to verify no regressions**

```bash
cd src/pki_validation && mix test --no-start 2>&1 | tail -10
```

Expected: all tests passing.

- [ ] **Step 6: Commit**

```bash
git add src/pki_validation/lib/pki_validation/ocsp/der_responder.ex \
        src/pki_validation/test/pki_validation/ocsp/der_responder_test.exs
git commit -m "fix: RFC 6960 nonce echoed on OCSP error responses (tryLater, unauthorized, internalError)"
```

---

## Task 2: Per-Issuer CRL Scoping

**Files:**
- Modify: `src/pki_validation/lib/pki_validation/crl_publisher.ex`
- Modify: `src/pki_validation/lib/pki_validation/api/router.ex`
- Modify: `src/pki_validation/test/crl_publisher_test.exs`

### Step 2.1 — Update existing tests first (they document the contract change)

- [ ] **Step 1: Update crl_publisher_test.exs to match new per-issuer API**

Replace the full content of `src/pki_validation/test/crl_publisher_test.exs`:

```elixir
defmodule PkiValidation.CrlPublisherTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.{TestHelper, Repo}
  alias PkiMnesia.Structs.{CertificateStatus, IssuerKey}
  alias PkiValidation.CrlPublisher

  setup do
    dir = TestHelper.setup_mnesia()

    {:ok, pid} = CrlPublisher.start_link(name: :test_crl, interval: :timer.hours(24))

    on_exit(fn ->
      if Process.alive?(pid), do: GenServer.stop(pid)
      TestHelper.teardown_mnesia(dir)
    end)

    %{crl: :test_crl}
  end

  test "get_current_crls returns empty map initially (no issuer keys)", %{crl: crl} do
    Process.sleep(200)
    {:ok, crls} = CrlPublisher.get_current_crls(crl)
    assert crls == %{}
  end

  test "regenerate returns per-issuer CRL map", %{crl: crl} do
    key_id = "key-regen-#{System.unique_integer()}"

    key = IssuerKey.new(%{
      id: key_id,
      ca_instance_id: "ca-1",
      key_alias: "regen-key",
      algorithm: "ECC_P256",
      status: "active",
      crl_strategy: "per_interval"
    })
    {:ok, _} = Repo.insert(key)

    {:ok, crls} = CrlPublisher.regenerate(crl)
    assert Map.has_key?(crls, key_id)
    assert crls[key_id].type == "X509CRL"
    assert crls[key_id].total_revoked == 0
  end

  test "regenerate scopes revoked certs per issuer", %{crl: crl} do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    key_a = "key-a-#{System.unique_integer()}"
    key_b = "key-b-#{System.unique_integer()}"

    for {key_id, alias_name} <- [{key_a, "key-a"}, {key_b, "key-b"}] do
      key = IssuerKey.new(%{
        id: key_id,
        ca_instance_id: "ca-1",
        key_alias: alias_name,
        algorithm: "ECC_P256",
        status: "active",
        crl_strategy: "per_interval"
      })
      {:ok, _} = Repo.insert(key)
    end

    cs_a = CertificateStatus.new(%{
      serial_number: "revoked-a",
      issuer_key_id: key_a,
      status: "revoked",
      revoked_at: now,
      revocation_reason: "keyCompromise"
    })
    cs_b = CertificateStatus.new(%{
      serial_number: "revoked-b",
      issuer_key_id: key_b,
      status: "revoked",
      revoked_at: now,
      revocation_reason: "cessationOfOperation"
    })
    {:ok, _} = Repo.insert(cs_a)
    {:ok, _} = Repo.insert(cs_b)

    {:ok, crls} = CrlPublisher.regenerate(crl)

    assert Map.has_key?(crls, key_a)
    assert Map.has_key?(crls, key_b)

    crl_a = crls[key_a]
    crl_b = crls[key_b]

    assert crl_a.total_revoked == 1
    assert Enum.any?(crl_a.revoked_certificates, &(&1.serial_number == "revoked-a"))
    refute Enum.any?(crl_a.revoked_certificates, &(&1.serial_number == "revoked-b"))

    assert crl_b.total_revoked == 1
    assert Enum.any?(crl_b.revoked_certificates, &(&1.serial_number == "revoked-b"))
    refute Enum.any?(crl_b.revoked_certificates, &(&1.serial_number == "revoked-a"))
  end

  test "inactive issuer key is skipped in CRL generation", %{crl: crl} do
    key_id = "key-inactive-#{System.unique_integer()}"
    key = IssuerKey.new(%{
      id: key_id,
      ca_instance_id: "ca-1",
      key_alias: "inactive-key",
      algorithm: "ECC_P256",
      status: "suspended",
      crl_strategy: "per_interval"
    })
    {:ok, _} = Repo.insert(key)

    {:ok, crls} = CrlPublisher.regenerate(crl)
    refute Map.has_key?(crls, key_id)
  end
end
```

- [ ] **Step 2: Run updated tests (expect failures — implementation not yet changed)**

```bash
cd src/pki_validation && mix test test/crl_publisher_test.exs --no-start 2>&1 | tail -20
```

Expected: failures on `get_current_crls` (function does not exist yet).

### Step 2.2 — Rewrite CrlPublisher

- [ ] **Step 3: Rewrite crl_publisher.ex with per-issuer state and API**

Replace the full file `src/pki_validation/lib/pki_validation/crl_publisher.ex`:

```elixir
defmodule PkiValidation.CrlPublisher do
  @moduledoc """
  CRL Publisher against Mnesia (RFC 5280 §5).

  Periodically generates one CRL per active IssuerKey. Each CRL is scoped to
  the revoked CertificateStatus records for that issuer — RFC 5280 requires
  each issuer to publish its own CRL. State is a map of
  %{issuer_key_id => crl_map}.

  For signed CRLs, calls `PkiCaEngine.KeyActivation.lease_status/2` +
  `Dispatcher.sign/2` — no separate SigningKeyStore needed since both engines
  run in the same tenant BEAM.
  """

  use GenServer
  require Logger

  alias PkiMnesia.{Repo, Structs.CertificateStatus, Structs.IssuerKey, Structs.PreSignedCrl}
  alias PkiCaEngine.{KeyActivation, KeyStore.Dispatcher}

  @default_interval_ms :timer.hours(1)
  @crl_validity_seconds 3600

  # -- Client API --

  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc """
  Returns the per-issuer CRL map: `%{issuer_key_id => crl_map}`.

  An empty map means no active IssuerKey records exist (or none have been
  generated yet). If the last generation had errors, the map may be missing
  entries for affected issuers.
  """
  def get_current_crls(server \\ __MODULE__) do
    GenServer.call(server, :get_crls)
  end

  @doc """
  Force regeneration of all per-issuer CRLs.
  Returns `{:ok, crls_map}` with the freshly generated data.
  """
  def regenerate(server \\ __MODULE__) do
    GenServer.call(server, :regenerate)
  end

  @doc """
  Build and return a signed CRL for the given issuer_key_id.

  Branches on the `crl_strategy` field of the associated `IssuerKey`:

    - `"per_interval"` (default) — requires an active key lease. Returns
      `{:error, :no_active_lease}` if no lease is present.
    - `"pre_signed"` — looks up the nearest `PreSignedCrl` record whose
      window covers the current time. Returns `{:error, :no_valid_pre_signed_crl}`
      if none is found.

  Options:
    - `:activation_server` — GenServer name/pid for KeyActivation (default: `KeyActivation`)
  """
  def signed_crl(issuer_key_id, opts \\ []) do
    activation_server = Keyword.get(opts, :activation_server, KeyActivation)

    case Repo.get(IssuerKey, issuer_key_id) do
      {:ok, nil} ->
        {:error, :issuer_key_not_found}

      {:ok, issuer_key} ->
        strategy = Map.get(issuer_key, :crl_strategy, "per_interval") || "per_interval"
        do_signed_crl(strategy, issuer_key_id, issuer_key, activation_server)

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp do_signed_crl("per_interval", issuer_key_id, issuer_key, activation_server) do
    status = KeyActivation.lease_status(activation_server, issuer_key_id)

    if Map.get(status, :active, false) do
      with {:ok, crl} <- do_generate_crl(issuer_key_id),
           crl_data <- :erlang.term_to_binary(crl),
           {:ok, signature} <- Dispatcher.sign(issuer_key_id, crl_data) do
        {:ok, Map.merge(crl, %{signature: signature, algorithm: issuer_key.algorithm})}
      else
        {:error, reason} ->
          {:error, {:signing_failed, reason}}
      end
    else
      {:error, :no_active_lease}
    end
  end

  defp do_signed_crl("pre_signed", issuer_key_id, _issuer_key, _activation_server) do
    now = DateTime.utc_now()

    case Repo.where(PreSignedCrl, fn crl ->
           crl.issuer_key_id == issuer_key_id and
             DateTime.compare(crl.valid_from, now) != :gt and
             DateTime.compare(crl.valid_until, now) == :gt
         end) do
      {:ok, [record | _]} ->
        {:ok, record.crl_der}

      {:ok, []} ->
        {:error, :no_valid_pre_signed_crl}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp do_signed_crl(unknown_strategy, _issuer_key_id, _issuer_key, _activation_server) do
    {:error, {:unknown_crl_strategy, unknown_strategy}}
  end

  # -- Server callbacks --

  @impl true
  def init(opts) do
    interval = Keyword.get(opts, :interval, @default_interval_ms)

    state = %{
      crls: %{},
      interval: interval,
      generation_error: false
    }

    Process.send_after(self(), :generate, 100)
    schedule_regeneration(interval)

    {:ok, state}
  end

  @impl true
  def handle_call(:get_crls, _from, state) do
    {:reply, {:ok, state.crls}, state}
  end

  @impl true
  def handle_call(:regenerate, _from, state) do
    case do_generate_all_crls() do
      {:ok, crls} ->
        {:reply, {:ok, crls}, %{state | crls: crls, generation_error: false}}

      {:error, _reason} ->
        {:reply, {:ok, state.crls}, %{state | generation_error: true}}
    end
  end

  @impl true
  def handle_info(:generate, state) do
    case do_generate_all_crls() do
      {:ok, crls} ->
        {:noreply, %{state | crls: crls, generation_error: false}}

      {:error, _reason} ->
        {:noreply, %{state | generation_error: true}}
    end
  end

  @impl true
  def handle_info(:regenerate, state) do
    new_state =
      case do_generate_all_crls() do
        {:ok, crls} ->
          %{state | crls: crls, generation_error: false}

        {:error, _reason} ->
          %{state | generation_error: true}
      end

    schedule_regeneration(state.interval)
    {:noreply, new_state}
  end

  # -- Private helpers --

  defp do_generate_all_crls do
    case Repo.all(IssuerKey) do
      {:ok, keys} ->
        crls =
          keys
          |> Enum.filter(fn key -> key.status == "active" end)
          |> Enum.reduce(%{}, fn key, acc ->
            case do_generate_crl(key.id) do
              {:ok, crl} ->
                Map.put(acc, key.id, crl)

              {:error, reason} ->
                Logger.warning(
                  "CRL generation skipped for issuer #{key.id}: #{inspect(reason)}"
                )

                acc
            end
          end)

        {:ok, crls}

      {:error, reason} ->
        Logger.error("Failed to query IssuerKeys for CRL generation: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp do_generate_crl(issuer_key_id) do
    case Repo.where(CertificateStatus, fn cs ->
           cs.status == "revoked" && cs.issuer_key_id == issuer_key_id
         end) do
      {:ok, revoked} ->
        revoked_certs =
          revoked
          |> Enum.map(fn cs ->
            %{
              serial_number: cs.serial_number,
              revoked_at: cs.revoked_at,
              reason: cs.revocation_reason
            }
          end)
          |> Enum.sort_by(& &1.revoked_at)

        {:ok, build_crl(revoked_certs)}

      {:error, reason} ->
        Logger.error("CRL generation failed for issuer #{issuer_key_id}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp build_crl(revoked_certs) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    %{
      type: "X509CRL",
      version: 2,
      this_update: DateTime.to_iso8601(now),
      next_update: now |> DateTime.add(@crl_validity_seconds, :second) |> DateTime.to_iso8601(),
      revoked_certificates: revoked_certs,
      total_revoked: length(revoked_certs)
    }
  end

  defp schedule_regeneration(interval) do
    Process.send_after(self(), :regenerate, interval)
  end
end
```

- [ ] **Step 4: Update router.ex — health endpoint and GET /crl**

In `src/pki_validation/lib/pki_validation/api/router.ex`, replace the `/health` handler:

```elixir
  get "/health" do
    crl_status =
      case PkiValidation.CrlPublisher.get_current_crls() do
        {:ok, crls} ->
          total = crls |> Enum.map(fn {_, crl} -> crl.total_revoked end) |> Enum.sum()
          %{issuer_count: map_size(crls), total_revoked: total}

        _ ->
          %{error: "unavailable"}
      end

    send_json(conn, 200, %{status: "ok", crl: crl_status})
  end
```

Replace the `GET /crl` handler:

```elixir
  get "/crl" do
    case PkiValidation.CrlPublisher.get_current_crls() do
      {:ok, crls} ->
        summary =
          Enum.map(crls, fn {issuer_key_id, crl} ->
            %{
              issuer_key_id: issuer_key_id,
              total_revoked: crl.total_revoked,
              this_update: crl.this_update,
              next_update: crl.next_update
            }
          end)

        send_json(conn, 200, %{crls: summary})

      {:error, reason} ->
        Logger.error("CRL fetch failed: #{inspect(reason)}")
        send_json(conn, 500, %{error: "CRL generation failed"})
    end
  end
```

- [ ] **Step 5: Run CRL publisher tests to verify they pass**

```bash
cd src/pki_validation && mix test test/crl_publisher_test.exs --no-start 2>&1 | tail -15
```

Expected: `4 tests, 0 failures`

- [ ] **Step 6: Run full suite to verify no regressions**

```bash
cd src/pki_validation && mix test --no-start 2>&1 | tail -10
```

Expected: all tests passing.

- [ ] **Step 7: Commit**

```bash
git add src/pki_validation/lib/pki_validation/crl_publisher.ex \
        src/pki_validation/lib/pki_validation/api/router.ex \
        src/pki_validation/test/crl_publisher_test.exs
git commit -m "fix: per-issuer CRL scoping in CrlPublisher — RFC 5280 §5 compliance"
```

---

## Task 3: PostgreSQL Validation Schema Cleanup

**Files:**
- Modify: `src/pki_platform_engine/lib/pki_platform_engine/provisioner.ex`
- Modify: `src/pki_platform_engine/lib/mix/tasks/pki.migrate_existing_tenants.ex`
- Modify: `src/pki_platform_engine/lib/pki_platform_engine/tenant_prefix.ex`
- Modify: `src/pki_validation/config/config.exs`
- Delete: `src/pki_platform_engine/priv/tenant_validation_schema.sql`
- Delete: 5 migration files in `src/pki_validation/priv/repo/migrations/`

No TDD step needed — these are pure deletions. Run platform engine tests after each group of changes.

- [ ] **Step 1: Remove validation migration from provisioner.ex**

In `src/pki_platform_engine/lib/pki_platform_engine/provisioner.ex`, find and remove these three lines from `run_tenant_migrations/1`:

```elixir
Logger.info("tenant_migration_start prefix=#{prefixes.validation_prefix} engine=validation")
apply_tenant_schema_sql("tenant_validation_schema.sql", "validation", prefixes.validation_prefix)
Logger.info("tenant_migration_done prefix=#{prefixes.validation_prefix} engine=validation")
```

- [ ] **Step 2: Remove validation steps from pki.migrate_existing_tenants**

In `src/pki_platform_engine/lib/mix/tasks/pki.migrate_existing_tenants.ex`, remove these two functions from the `errors` list inside the `for` loop:

```elixir
fn -> Provisioner.ensure_schema_exists(prefixes.validation_prefix) end,
fn -> Provisioner.apply_tenant_schema_file("tenant_validation_schema.sql", "validation", prefixes.validation_prefix) end
```

The resulting list should have only the audit functions:

```elixir
errors =
  [
    fn -> Provisioner.ensure_schema_exists(prefixes.audit_prefix) end,
    fn -> Provisioner.apply_tenant_schema_file("tenant_audit_schema.sql", "audit", prefixes.audit_prefix) end
  ]
  |> Enum.flat_map(fn f ->
```

- [ ] **Step 3: Update TenantPrefix — remove validation_prefix/1, update pattern**

Replace the full content of `src/pki_platform_engine/lib/pki_platform_engine/tenant_prefix.ex`:

```elixir
defmodule PkiPlatformEngine.TenantPrefix do
  @moduledoc """
  Generates PostgreSQL schema prefixes for schema-per-tenant isolation.

  Each tenant gets three schemas: `t_{uuid_hex}_ca`, `t_{uuid_hex}_ra`,
  and `t_{uuid_hex}_audit`. The uuid_hex is the full 32 hex chars of the
  tenant UUID (hyphens stripped). The longest prefix is `t_<32hex>_audit`
  = 39 chars, well within PostgreSQL's 63-char limit.

  Validation state lives in Mnesia on the tenant BEAM node — there are no
  `t_<hex>_validation` PostgreSQL schemas.
  """

  @prefix_pattern ~r/\At_[0-9a-f]{32}_(ca|ra|audit)\z/

  @doc "CA schema prefix for a tenant."
  def ca_prefix(tenant_id), do: "t_#{uuid_hex(tenant_id)}_ca"

  @doc "RA schema prefix for a tenant."
  def ra_prefix(tenant_id), do: "t_#{uuid_hex(tenant_id)}_ra"

  @doc "Audit schema prefix for a tenant."
  def audit_prefix(tenant_id), do: "t_#{uuid_hex(tenant_id)}_audit"

  @doc "Returns all three prefixes as a map."
  def all_prefixes(tenant_id) do
    %{
      ca_prefix: ca_prefix(tenant_id),
      ra_prefix: ra_prefix(tenant_id),
      audit_prefix: audit_prefix(tenant_id)
    }
  end

  @doc """
  Validates that a prefix string matches the expected pattern.
  Use this at every point where a prefix enters raw SQL.
  Raises ArgumentError if the prefix is invalid.
  """
  def validate_prefix!(prefix) when is_binary(prefix) do
    unless prefix =~ @prefix_pattern do
      raise ArgumentError,
        "Invalid schema prefix: #{inspect(prefix)}. " <>
        "Expected format: t_<32hex>_(ca|ra|audit)"
    end
    prefix
  end

  @doc "Returns the compiled regex pattern for prefix validation."
  def prefix_pattern, do: @prefix_pattern

  defp uuid_hex(id) when is_binary(id) do
    stripped = String.replace(id, "-", "")

    unless stripped =~ ~r/\A[0-9a-f]{32}\z/ do
      raise ArgumentError,
        "Invalid UUID for schema prefix generation: #{inspect(id)}. " <>
        "Expected a 32-hex-char UUID (with or without hyphens)."
    end

    stripped
  end
end
```

- [ ] **Step 4: Remove ecto_repos from pki_validation config**

In `src/pki_validation/config/config.exs`, find and remove the line:

```elixir
config :pki_validation, ecto_repos: [PkiValidation.Repo]
```

- [ ] **Step 5: Delete orphaned SQL file and migration files**

```bash
rm src/pki_platform_engine/priv/tenant_validation_schema.sql
rm src/pki_validation/priv/repo/migrations/20260316000001_create_certificate_status.exs
rm src/pki_validation/priv/repo/migrations/20260326000001_switch_to_uuidv7.exs
rm src/pki_validation/priv/repo/migrations/20260407000001_add_issuer_name_hash.exs
rm src/pki_validation/priv/repo/migrations/20260407000002_create_signing_key_config.exs
rm src/pki_validation/priv/repo/migrations/20260407000003_create_crl_metadata.exs
```

- [ ] **Step 6: Verify platform engine compiles and tests pass**

```bash
cd src/pki_platform_engine && mix compile 2>&1 | grep -E "error|warning" | grep -v "^$"
cd src/pki_platform_engine && mix test 2>&1 | tail -10
```

Expected: no compilation errors (warnings about unused `validation_prefix` callers would indicate missed cleanup — fix if any appear). Tests passing.

- [ ] **Step 7: Check for any remaining callers of validation_prefix or tenant_validation_schema**

```bash
grep -r "validation_prefix\|tenant_validation_schema\|PkiValidation.Repo" \
  src/pki_platform_engine src/pki_validation --include="*.ex" --include="*.exs" -l
```

Expected: no output (no remaining callers). If any files appear, update them.

- [ ] **Step 8: Commit**

```bash
git add src/pki_platform_engine/lib/pki_platform_engine/provisioner.ex \
        src/pki_platform_engine/lib/mix/tasks/pki.migrate_existing_tenants.ex \
        src/pki_platform_engine/lib/pki_platform_engine/tenant_prefix.ex \
        src/pki_validation/config/config.exs
git rm src/pki_platform_engine/priv/tenant_validation_schema.sql \
       src/pki_validation/priv/repo/migrations/20260316000001_create_certificate_status.exs \
       src/pki_validation/priv/repo/migrations/20260326000001_switch_to_uuidv7.exs \
       src/pki_validation/priv/repo/migrations/20260407000001_add_issuer_name_hash.exs \
       src/pki_validation/priv/repo/migrations/20260407000002_create_signing_key_config.exs \
       src/pki_validation/priv/repo/migrations/20260407000003_create_crl_metadata.exs
git commit -m "fix: remove orphaned PostgreSQL validation schemas — all validation state is in Mnesia"
```

---

## Task 4: Architecture Documentation Updates

**Files:**
- Modify: `README.md`
- Modify: `docs/PKI-System-Technical-Summary.md`
- Modify: `CLAUDE.md`
- Modify: `deploy/DEPLOYMENT.md`
- Modify: `TODOS.md`

No tests for docs. Each step is a targeted edit with a verification grep.

- [ ] **Step 1: Replace README.md architecture section**

In `README.md`, replace everything from `## Architecture` through the closing ` ``` ` of the diagram (the ASCII diagram block ending at the closing triple-backtick before the port table), plus the port table that follows, with:

```markdown
## Architecture

```
Internet
    │
    ▼
┌─────────────────────────────────────┐
│  Caddy (80/443)                     │
│  admin.* → pki_platform :4006       │
│  <tenant>.* → pki_tenant (per-node) │
└────────┬────────────────────────────┘
         │
┌────────▼─────────────────────────────────────┐
│  pki_platform BEAM (1 node)                   │
│  Platform portal :4006                        │
│  Tenant lifecycle management                  │
│  PostgreSQL: tenant registry, platform users, │
│              platform audit trail             │
└────────┬─────────────────────────────────────┘
         │  :peer spawn / distributed Erlang
┌────────▼─────────────────────────────────────┐
│  pki_tenant BEAM (one node per tenant)        │
│  CA portal + CA engine (in-process)           │
│  RA portal + RA engine (in-process)           │
│  Validation: OCSP/CRL (in-process)            │
│  State: local Mnesia (disc_copies)            │
└──────────────────────────────────────────────┘
```

| Component | Purpose |
|-----------|---------|
| pki_platform | Platform portal + tenant lifecycle; Caddy routes `admin.*` here |
| pki_tenant | Per-tenant BEAM — CA engine, RA engine, OCSP/CRL, CA/RA portal UI |
| PostgreSQL | Platform-only: tenant registry, platform users, platform audit trail |
| Mnesia | Per-tenant state: keys, certificates, certificate status, CRL data |
| SoftHSM2 / HSM | PKCS#11 key storage for CA signing keys |
```

- [ ] **Step 2: Verify README.md no longer mentions old port numbers**

```bash
grep -n ":4001\|:4002\|:4003\|:4004\|:4005\|CA Engine\|RA Engine\|pki_portals" README.md
```

Expected: no output (or only in "What's New" historical notes — those are fine to leave).

- [ ] **Step 3: Replace the architecture diagram in PKI-System-Technical-Summary.md**

In `docs/PKI-System-Technical-Summary.md`, replace the `## System Architecture` section (from `## System Architecture` through the closing paragraph "Each box runs as an independent Erlang/OTP node…") with:

```markdown
## System Architecture

```
Internet
    │
    ▼
┌─────────────────────────────────────┐
│  Caddy (80/443)                     │
│  admin.* → pki_platform :4006       │
│  <tenant>.* → pki_tenant (per-node) │
└────────┬────────────────────────────┘
         │
┌────────▼─────────────────────────────────────┐
│  pki_platform BEAM (1 node)                   │
│  Platform portal :4006                        │
│  Tenant lifecycle management                  │
│  PostgreSQL: tenant registry, platform users, │
│              platform audit trail             │
└────────┬─────────────────────────────────────┘
         │  :peer spawn / distributed Erlang
┌────────▼─────────────────────────────────────┐
│  pki_tenant BEAM (one node per tenant)        │
│  CA portal + CA engine (in-process)           │
│  RA portal + RA engine (in-process)           │
│  Validation: OCSP/CRL (in-process)            │
│  State: local Mnesia (disc_copies)            │
└──────────────────────────────────────────────┘
```

The platform BEAM manages tenant lifecycle (provision, deprovision, spawn). Each tenant gets its own BEAM node with full CA/RA/Validation capability. Portals and engines are co-located in the tenant BEAM — no inter-process HTTP between them. OCSP and CRL requests are served from the same tenant BEAM; CDP/OCSP URLs in issued certificates point at the tenant's subdomain.

PostgreSQL is used only for platform-tier state (tenant registry, platform user accounts, platform audit trail). All CA, RA, and validation state lives in local Mnesia on the tenant BEAM node — each tenant is isolated by process boundary, not database schema.
```

- [ ] **Step 4: Update CLAUDE.md Architecture section**

In `CLAUDE.md`, replace the `## Architecture` section (from `## Architecture` through the end of the `### Registration Authority` subsection) with:

```markdown
## Architecture

The system runs two tiers of BEAM nodes:

**Platform tier (1 node):** `pki_platform` handles tenant lifecycle (provision, deprovision, :peer-spawn per-tenant BEAM), platform user management, and platform audit trail. Backed by PostgreSQL. Caddy routes `admin.*` to this node on port 4006.

**Tenant tier (one node per tenant):** Each tenant gets a dedicated `pki_tenant` BEAM node containing:
- **CA portal** — Phoenix LiveView UI for CA admin, key manager, auditor roles
- **CA engine** — key ceremony, issuer key management, certificate signing (in-process, no HTTP API)
- **RA portal** — Phoenix LiveView UI for RA admin, officer, auditor roles
- **RA engine** — CSR processing, certificate profile config (in-process, no HTTP API)
- **pki_validation** — OCSP responder + CRL publisher (in-process, served from tenant subdomain)
- **Mnesia** — local disc_copies storage for all CA/RA/validation state

Portals call engines directly (in-process function calls), not via HTTP. PostgreSQL is never touched by tenant nodes — all tenant state is in Mnesia.

### Supported Certificate Types
- **KAZ-SIGN** (Malaysia local PQC algorithm)
- **ML-DSA** (NIST PQC standard)
- **SLH-DSA** (NIST PQC hash-based)
- **RSA & ECC** (classical, for migration compatibility)
```

- [ ] **Step 5: Remove warning banner from DEPLOYMENT.md**

In `deploy/DEPLOYMENT.md`, remove lines 4-9 (the blockquote starting with `> **⚠️ Doc rewrite pending (Milestone 5).**` through `> have already been updated — this Markdown is the laggard.`).

The file should now start:

```
# PKI CA System — Production Deployment Guide
## BEAM Direct Deployment (No Containers)

This guide covers deploying all PKI services as native Elixir/OTP releases supervised
by systemd.
```

Verify:

```bash
head -8 deploy/DEPLOYMENT.md
```

Expected: no `⚠️` or "Doc rewrite pending" text.

- [ ] **Step 6: Close TODOS.md validation repo wiring item**

In `TODOS.md`, move the "Per-tenant schema mode: validation repo wiring" entry from `## Open` to `## Completed`. Update it to read:

```markdown
### Per-tenant schema mode: validation repo wiring
**Completed:** 2026-04-27 (this PR)
PostgreSQL `t_<hex>_validation` tables removed from provisioning and migrate task.
`validation_prefix/1` removed from `TenantPrefix`. Five orphaned Ecto migration files
and `ecto_repos: [PkiValidation.Repo]` config deleted. All validation state uses Mnesia
on the tenant BEAM node — no PostgreSQL validation schema was ever written or read.
```

- [ ] **Step 7: Verify docs compile cleanly (no broken references)**

```bash
grep -r "validation_prefix\|:4001\|:4002\|:4003\|:4004\|:4005\|schema-per-tenant\|CA Engine.*:40\|RA Engine.*:40" \
  README.md docs/PKI-System-Technical-Summary.md CLAUDE.md deploy/DEPLOYMENT.md TODOS.md
```

Expected: no output (no stale references remain).

- [ ] **Step 8: Commit**

```bash
git add README.md docs/PKI-System-Technical-Summary.md CLAUDE.md deploy/DEPLOYMENT.md TODOS.md
git commit -m "docs: update architecture docs to one-BEAM-node-per-tenant model"
```

---

## Final Verification

- [ ] **Run pki_validation full suite**

```bash
cd src/pki_validation && mix test --no-start 2>&1 | tail -5
```

Expected: all tests passing, 0 failures.

- [ ] **Run pki_platform_engine full suite**

```bash
cd src/pki_platform_engine && mix test 2>&1 | tail -5
```

Expected: all tests passing, 0 failures.

- [ ] **Confirm no orphaned references**

```bash
grep -r "PkiValidation.Repo\|tenant_validation_schema\|validation_prefix" \
  src/ --include="*.ex" --include="*.exs" --include="*.sql" -l
```

Expected: no output.
