# Auditor Witness & Async Key Ceremony Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform the key ceremony into a multi-participant async flow where ca_admin initiates, key managers independently accept shares (own key label + password), and auditor witnesses each phase gate — all time-windowed with real-time PubSub sync.

**Architecture:** DB migrations add columns to key_ceremonies/threshold_shares and a new ceremony_attestations table. A CustodianPasswordStore GenServer holds passwords in ETS (never disk). A CeremonyOrchestrator module coordinates phase transitions and triggers atomic keygen. A CeremonyWatchdog GenServer enforces time windows. Three LiveView pages (admin, custodian, witness) communicate via PubSub. The existing SyncCeremony backend is reused for keygen/split/encrypt.

**Tech Stack:** Elixir/Phoenix, Ecto migrations, ETS, GenServer, Phoenix.PubSub, LiveView, existing PkiCrypto/Shamir

---

## File Structure

### New Files (CA Engine — backend)

| File | Responsibility |
|------|----------------|
| `src/pki_ca_engine/priv/repo/migrations/TIMESTAMP_add_ceremony_witness_columns.exs` | Add auditor_user_id, time_window_hours to key_ceremonies; key_label, status, accepted_at to threshold_shares; create ceremony_attestations table |
| `src/pki_ca_engine/lib/pki_ca_engine/schema/ceremony_attestation.ex` | Ecto schema for ceremony_attestations |
| `src/pki_ca_engine/lib/pki_ca_engine/ceremony_orchestrator.ex` | Phase transition logic, triggers atomic keygen when ready |

### New Files (CA Portal — frontend/services)

| File | Responsibility |
|------|----------------|
| `src/pki_ca_portal/lib/pki_ca_portal/custodian_password_store.ex` | GenServer + ETS for holding custodian passwords in memory |
| `src/pki_ca_portal/lib/pki_ca_portal/ceremony_watchdog.ex` | GenServer that checks for expired ceremonies every minute |
| `src/pki_ca_portal/lib/pki_ca_portal/ceremony_notifications.ex` | Async email notifications for ceremony events |
| `src/pki_ca_portal/lib/pki_ca_portal_web/live/ceremony_custodian_live.ex` | Key manager share acceptance page |
| `src/pki_ca_portal/lib/pki_ca_portal_web/live/ceremony_witness_live.ex` | Auditor witness page |

### Modified Files

| File | Changes |
|------|---------|
| `src/pki_ca_engine/lib/pki_ca_engine/schema/key_ceremony.ex` | Add new fields, update valid statuses |
| `src/pki_ca_engine/lib/pki_ca_engine/schema/threshold_share.ex` | Add key_label, status, accepted_at fields; relax encrypted_share required validation |
| `src/pki_ca_portal/lib/pki_ca_portal_web/router.ex` | Add /ceremony/custodian and /ceremony/witness routes |
| `src/pki_ca_portal/lib/pki_ca_portal_web/live/auth_hook.ex` | Update RBAC: key_manager gets CeremonyCustodianLive, auditor gets CeremonyWitnessLive, key_manager loses CeremonyLive |
| `src/pki_ca_portal/lib/pki_ca_portal_web/live/ceremony_live.ex` | Replace wizard with initiation form + progress dashboard |
| `src/pki_ca_portal/lib/pki_ca_portal/application.ex` | Add CustodianPasswordStore + CeremonyWatchdog to supervision tree |
| `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client.ex` | Add new client functions for attestations and share acceptance |
| `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/direct.ex` | Implement new client functions |

---

### Task 1: Database Migration

**Files:**
- Create: `src/pki_ca_engine/priv/repo/migrations/20260403100000_add_ceremony_witness_columns.exs`
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/schema/key_ceremony.ex`
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/schema/threshold_share.ex`
- Create: `src/pki_ca_engine/lib/pki_ca_engine/schema/ceremony_attestation.ex`

- [ ] **Step 1: Create migration**

```elixir
# src/pki_ca_engine/priv/repo/migrations/20260403100000_add_ceremony_witness_columns.exs
defmodule PkiCaEngine.Repo.Migrations.AddCeremonyWitnessColumns do
  use Ecto.Migration

  def change do
    # Add columns to key_ceremonies
    alter table(:key_ceremonies) do
      add :auditor_user_id, :binary_id
      add :time_window_hours, :integer, default: 24
    end

    # Add columns to threshold_shares
    alter table(:threshold_shares) do
      add :key_label, :string
      add :status, :string, default: "pending"
      add :accepted_at, :utc_datetime
    end

    # Create ceremony_attestations table
    create table(:ceremony_attestations, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :ceremony_id, references(:key_ceremonies, type: :binary_id, on_delete: :delete_all), null: false
      add :auditor_user_id, :binary_id, null: false
      add :phase, :string, null: false
      add :attested_at, :utc_datetime, null: false
      add :details, :map, default: %{}

      timestamps()
    end

    create index(:ceremony_attestations, [:ceremony_id])
    create unique_index(:ceremony_attestations, [:ceremony_id, :phase])
  end
end
```

- [ ] **Step 2: Update KeyCeremony schema**

In `src/pki_ca_engine/lib/pki_ca_engine/schema/key_ceremony.ex`:

Add to the `@statuses` list: `"preparing"` and `"generating"`.

Change: `@statuses ["initiated", "in_progress", "preparing", "generating", "completed", "failed"]`

Add fields to the schema block:
```elixir
    field :auditor_user_id, :binary_id
    field :time_window_hours, :integer, default: 24
```

Add `:auditor_user_id` and `:time_window_hours` to the `cast/3` fields list in `changeset/2`.

- [ ] **Step 3: Update ThresholdShare schema**

In `src/pki_ca_engine/lib/pki_ca_engine/schema/threshold_share.ex`:

Add fields to the schema block:
```elixir
    field :key_label, :string
    field :status, :string, default: "pending"
    field :accepted_at, :utc_datetime
```

Add a new `placeholder_changeset/2` for creating pending shares (no encrypted_share required):
```elixir
  def placeholder_changeset(share, attrs) do
    share
    |> cast(attrs, [:issuer_key_id, :custodian_user_id, :share_index, :min_shares, :total_shares, :key_label, :status, :accepted_at])
    |> validate_required([:issuer_key_id, :custodian_user_id, :share_index, :min_shares, :total_shares])
    |> foreign_key_constraint(:issuer_key_id)
    |> unique_constraint([:issuer_key_id, :custodian_user_id, :share_index])
    |> maybe_generate_id()
  end

  def accept_changeset(share, attrs) do
    share
    |> cast(attrs, [:key_label, :status, :accepted_at, :encrypted_share])
    |> validate_required([:key_label, :status, :encrypted_share])
  end
```

Add `:key_label`, `:status`, `:accepted_at` to the existing `changeset/2` cast list.

- [ ] **Step 4: Create CeremonyAttestation schema**

```elixir
# src/pki_ca_engine/lib/pki_ca_engine/schema/ceremony_attestation.ex
defmodule PkiCaEngine.Schema.CeremonyAttestation do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  @phases ["preparation", "key_generation", "completion"]

  schema "ceremony_attestations" do
    field :auditor_user_id, :binary_id
    field :phase, :string
    field :attested_at, :utc_datetime
    field :details, :map, default: %{}

    belongs_to :ceremony, PkiCaEngine.Schema.KeyCeremony

    timestamps()
  end

  def changeset(attestation, attrs) do
    attestation
    |> cast(attrs, [:ceremony_id, :auditor_user_id, :phase, :attested_at, :details])
    |> validate_required([:ceremony_id, :auditor_user_id, :phase, :attested_at])
    |> validate_inclusion(:phase, @phases)
    |> foreign_key_constraint(:ceremony_id)
    |> unique_constraint([:ceremony_id, :phase])
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

- [ ] **Step 5: Run migration on dev DB**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_engine && mix ecto.migrate
```

- [ ] **Step 6: Compile and verify**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_engine && mix compile
```

- [ ] **Step 7: Commit**

```bash
git add src/pki_ca_engine/priv/repo/migrations/20260403100000_add_ceremony_witness_columns.exs \
        src/pki_ca_engine/lib/pki_ca_engine/schema/key_ceremony.ex \
        src/pki_ca_engine/lib/pki_ca_engine/schema/threshold_share.ex \
        src/pki_ca_engine/lib/pki_ca_engine/schema/ceremony_attestation.ex
git commit -m "feat(ca-engine): add ceremony witness DB schema — attestations table, share status, auditor fields"
```

---

### Task 2: CustodianPasswordStore (ETS GenServer)

**Files:**
- Create: `src/pki_ca_portal/lib/pki_ca_portal/custodian_password_store.ex`
- Create: `src/pki_ca_portal/test/pki_ca_portal/custodian_password_store_test.exs`
- Modify: `src/pki_ca_portal/lib/pki_ca_portal/application.ex`

- [ ] **Step 1: Write tests**

```elixir
# src/pki_ca_portal/test/pki_ca_portal/custodian_password_store_test.exs
defmodule PkiCaPortal.CustodianPasswordStoreTest do
  use ExUnit.Case, async: false

  alias PkiCaPortal.CustodianPasswordStore

  setup do
    CustodianPasswordStore.clear_all()
    :ok
  end

  describe "store_password/3" do
    test "stores and retrieves a password" do
      :ok = CustodianPasswordStore.store_password("ceremony-1", "user-1", "secret123")
      assert {:ok, "secret123"} = CustodianPasswordStore.get_password("ceremony-1", "user-1")
    end
  end

  describe "get_password/2" do
    test "returns error for missing password" do
      assert {:error, :not_found} = CustodianPasswordStore.get_password("no", "no")
    end
  end

  describe "get_all_passwords/1" do
    test "returns all passwords for a ceremony" do
      :ok = CustodianPasswordStore.store_password("ceremony-1", "user-1", "pass1")
      :ok = CustodianPasswordStore.store_password("ceremony-1", "user-2", "pass2")
      :ok = CustodianPasswordStore.store_password("ceremony-2", "user-3", "pass3")

      passwords = CustodianPasswordStore.get_all_passwords("ceremony-1")
      assert length(passwords) == 2
      assert {"user-1", "pass1"} in passwords
      assert {"user-2", "pass2"} in passwords
    end
  end

  describe "wipe_ceremony/1" do
    test "removes all passwords for a ceremony" do
      :ok = CustodianPasswordStore.store_password("ceremony-1", "user-1", "pass1")
      :ok = CustodianPasswordStore.store_password("ceremony-1", "user-2", "pass2")

      :ok = CustodianPasswordStore.wipe_ceremony("ceremony-1")

      assert {:error, :not_found} = CustodianPasswordStore.get_password("ceremony-1", "user-1")
      assert {:error, :not_found} = CustodianPasswordStore.get_password("ceremony-1", "user-2")
    end
  end

  describe "has_all_passwords?/2" do
    test "returns true when all users have submitted" do
      :ok = CustodianPasswordStore.store_password("c1", "u1", "p1")
      :ok = CustodianPasswordStore.store_password("c1", "u2", "p2")

      assert CustodianPasswordStore.has_all_passwords?("c1", ["u1", "u2"])
    end

    test "returns false when some users are missing" do
      :ok = CustodianPasswordStore.store_password("c1", "u1", "p1")

      refute CustodianPasswordStore.has_all_passwords?("c1", ["u1", "u2"])
    end
  end
end
```

- [ ] **Step 2: Implement CustodianPasswordStore**

```elixir
# src/pki_ca_portal/lib/pki_ca_portal/custodian_password_store.ex
defmodule PkiCaPortal.CustodianPasswordStore do
  @moduledoc """
  ETS-backed in-memory store for custodian passwords during ceremony preparation.

  Passwords are NEVER written to disk or DB. They exist in memory only
  for the duration of the preparation phase, then are wiped after share
  encryption or on ceremony failure/expiry.
  """

  use GenServer

  @table :ceremony_custodian_passwords

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def store_password(ceremony_id, user_id, password) do
    :ets.insert(@table, {{ceremony_id, user_id}, password})
    :ok
  end

  def get_password(ceremony_id, user_id) do
    case :ets.lookup(@table, {ceremony_id, user_id}) do
      [{{^ceremony_id, ^user_id}, password}] -> {:ok, password}
      [] -> {:error, :not_found}
    end
  end

  def get_all_passwords(ceremony_id) do
    :ets.tab2list(@table)
    |> Enum.filter(fn {{cid, _uid}, _pw} -> cid == ceremony_id end)
    |> Enum.map(fn {{_cid, uid}, pw} -> {uid, pw} end)
  end

  def has_all_passwords?(ceremony_id, user_ids) do
    stored = get_all_passwords(ceremony_id) |> Enum.map(&elem(&1, 0))
    Enum.all?(user_ids, &(&1 in stored))
  end

  def wipe_ceremony(ceremony_id) do
    :ets.tab2list(@table)
    |> Enum.filter(fn {{cid, _uid}, _pw} -> cid == ceremony_id end)
    |> Enum.each(fn {key, _pw} -> :ets.delete(@table, key) end)

    :ok
  end

  def clear_all do
    :ets.delete_all_objects(@table)
    :ok
  end

  @impl true
  def init(_opts) do
    table = :ets.new(@table, [:named_table, :set, :public, read_concurrency: true])
    {:ok, %{table: table}}
  end
end
```

- [ ] **Step 3: Add to application supervision tree**

In `src/pki_ca_portal/lib/pki_ca_portal/application.ex`, add `PkiCaPortal.CustodianPasswordStore` to children list after `SessionStore`.

- [ ] **Step 4: Run tests**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_portal && MIX_ENV=test elixir --sname test_pwd -S mix test test/pki_ca_portal/custodian_password_store_test.exs --trace
```

- [ ] **Step 5: Commit**

```bash
git add src/pki_ca_portal/lib/pki_ca_portal/custodian_password_store.ex \
        src/pki_ca_portal/test/pki_ca_portal/custodian_password_store_test.exs \
        src/pki_ca_portal/lib/pki_ca_portal/application.ex
git commit -m "feat(ca-portal): CustodianPasswordStore — ETS-backed in-memory password storage"
```

---

### Task 3: CeremonyOrchestrator (Phase Transitions + Atomic Keygen)

**Files:**
- Create: `src/pki_ca_engine/lib/pki_ca_engine/ceremony_orchestrator.ex`
- Create: `src/pki_ca_engine/test/pki_ca_engine/ceremony_orchestrator_test.exs`

- [ ] **Step 1: Implement CeremonyOrchestrator**

```elixir
# src/pki_ca_engine/lib/pki_ca_engine/ceremony_orchestrator.ex
defmodule PkiCaEngine.CeremonyOrchestrator do
  @moduledoc """
  Orchestrates multi-participant ceremony phase transitions.

  Handles:
  - Creating ceremonies with participant assignments
  - Tracking custodian readiness
  - Recording auditor attestations
  - Triggering atomic key generation when all participants are ready
  """

  alias PkiCaEngine.TenantRepo
  alias PkiCaEngine.Schema.{KeyCeremony, IssuerKey, ThresholdShare, CeremonyAttestation}
  alias PkiCaEngine.{IssuerKeyManagement, KeystoreManagement}
  alias PkiCaEngine.KeyCeremony.{SyncCeremony, ShareEncryption}
  import Ecto.Query

  @doc """
  Initiates a ceremony with participant assignments.

  Creates KeyCeremony, IssuerKey, and placeholder ThresholdShare records.
  """
  def initiate(tenant_id, ca_instance_id, params) do
    repo = TenantRepo.ca_repo(tenant_id)

    with :ok <- validate_threshold(params.threshold_k, params.threshold_n),
         :ok <- validate_participants(params.custodian_user_ids, params.threshold_n),
         {:ok, _keystore} <- KeystoreManagement.get_keystore(tenant_id, params.keystore_id) do
      window_hours = Map.get(params, :time_window_hours, 24)
      window_expires_at = DateTime.utc_now() |> DateTime.add(window_hours * 3600, :second)

      repo.transaction(fn ->
        case IssuerKeyManagement.create_issuer_key(tenant_id, ca_instance_id, %{
               key_alias: Map.get(params, :key_alias) || "key-#{System.unique_integer([:positive])}",
               algorithm: params.algorithm,
               is_root: Map.get(params, :is_root, true),
               threshold_config: %{k: params.threshold_k, n: params.threshold_n}
             }) do
          {:ok, issuer_key} ->
            ceremony_attrs = %{
              ca_instance_id: ca_instance_id,
              issuer_key_id: issuer_key.id,
              ceremony_type: "sync",
              status: "preparing",
              algorithm: params.algorithm,
              keystore_id: params.keystore_id,
              threshold_k: params.threshold_k,
              threshold_n: params.threshold_n,
              domain_info: Map.get(params, :domain_info, %{}),
              initiated_by: params.initiated_by,
              auditor_user_id: params.auditor_user_id,
              time_window_hours: window_hours,
              window_expires_at: window_expires_at,
              participants: %{
                custodians: params.custodian_user_ids,
                auditor: params.auditor_user_id
              }
            }

            case %KeyCeremony{} |> KeyCeremony.changeset(ceremony_attrs) |> repo.insert() do
              {:ok, ceremony} ->
                # Create placeholder shares for each custodian
                shares =
                  params.custodian_user_ids
                  |> Enum.with_index(1)
                  |> Enum.map(fn {user_id, index} ->
                    {:ok, share} =
                      %ThresholdShare{}
                      |> ThresholdShare.placeholder_changeset(%{
                        issuer_key_id: issuer_key.id,
                        custodian_user_id: user_id,
                        share_index: index,
                        min_shares: params.threshold_k,
                        total_shares: params.threshold_n,
                        status: "pending"
                      })
                      |> repo.insert()

                    share
                  end)

                {ceremony, issuer_key, shares}

              {:error, reason} ->
                repo.rollback(reason)
            end

          {:error, reason} ->
            repo.rollback(reason)
        end
      end)
    end
  end

  @doc """
  Records a custodian accepting their share (key_label stored in DB, password NOT stored in DB).
  """
  def accept_share(tenant_id, ceremony_id, user_id, key_label) do
    repo = TenantRepo.ca_repo(tenant_id)

    case get_ceremony(repo, ceremony_id) do
      {:ok, ceremony} when ceremony.status == "preparing" ->
        case repo.one(
               from s in ThresholdShare,
                 where: s.issuer_key_id == ^ceremony.issuer_key_id and
                        s.custodian_user_id == ^user_id and
                        s.status == "pending"
             ) do
          nil ->
            {:error, :share_not_found}

          share ->
            share
            |> Ecto.Changeset.change(%{
              key_label: key_label,
              status: "accepted",
              accepted_at: DateTime.utc_now()
            })
            |> repo.update()
        end

      {:ok, _} -> {:error, :invalid_ceremony_status}
      error -> error
    end
  end

  @doc """
  Records an auditor attestation for a ceremony phase.
  """
  def attest(tenant_id, ceremony_id, auditor_user_id, phase, details \\ %{}) do
    repo = TenantRepo.ca_repo(tenant_id)

    case get_ceremony(repo, ceremony_id) do
      {:ok, ceremony} when ceremony.auditor_user_id == auditor_user_id ->
        %CeremonyAttestation{}
        |> CeremonyAttestation.changeset(%{
          ceremony_id: ceremony_id,
          auditor_user_id: auditor_user_id,
          phase: phase,
          attested_at: DateTime.utc_now(),
          details: details
        })
        |> repo.insert()

      {:ok, _} -> {:error, :not_assigned_auditor}
      error -> error
    end
  end

  @doc """
  Checks if all custodians have accepted and preparation attestation exists.
  Returns :ready if the ceremony can proceed to key generation.
  """
  def check_readiness(tenant_id, ceremony_id) do
    repo = TenantRepo.ca_repo(tenant_id)

    case get_ceremony(repo, ceremony_id) do
      {:ok, ceremony} when ceremony.status == "preparing" ->
        all_accepted =
          repo.aggregate(
            from(s in ThresholdShare,
              where: s.issuer_key_id == ^ceremony.issuer_key_id and s.status == "pending"
            ),
            :count
          ) == 0

        prep_attested =
          repo.exists?(
            from(a in CeremonyAttestation,
              where: a.ceremony_id == ^ceremony_id and a.phase == "preparation"
            )
          )

        if all_accepted and prep_attested, do: :ready, else: :waiting

      {:ok, _} -> {:error, :invalid_status}
      error -> error
    end
  end

  @doc """
  Executes atomic key generation: keygen → sign → split → encrypt → wipe.

  `custodian_passwords` is a list of `{user_id, password}` tuples from ETS.
  """
  def execute_keygen(tenant_id, ceremony_id, custodian_passwords) do
    repo = TenantRepo.ca_repo(tenant_id)

    case get_ceremony(repo, ceremony_id) do
      {:ok, ceremony} when ceremony.status == "preparing" ->
        # Transition to generating
        ceremony
        |> Ecto.Changeset.change(%{status: "generating"})
        |> repo.update!()

        # Generate keypair
        case SyncCeremony.generate_keypair(ceremony.algorithm) do
          {:ok, %{public_key: pub, private_key: priv}} ->
            fingerprint = :crypto.hash(:sha256, pub) |> Base.encode16(case: :lower)

            # Sign cert or generate CSR
            is_root = Map.get(ceremony.domain_info || %{}, "is_root", true)
            subject_dn = Map.get(ceremony.domain_info || %{}, "subject_dn", "/CN=CA-#{ceremony.id}")

            {cert_or_csr_result, cert_der, cert_pem, csr_pem} =
              if is_root do
                case generate_self_signed(priv, subject_dn) do
                  {:ok, der, pem} -> {:ok, der, pem, nil}
                  error -> {error, nil, nil, nil}
                end
              else
                case generate_csr(priv, subject_dn) do
                  {:ok, pem} -> {:ok, nil, nil, pem}
                  error -> {error, nil, nil, nil}
                end
              end

            case cert_or_csr_result do
              :ok ->
                # Split private key
                case PkiCrypto.Shamir.split(priv, ceremony.threshold_k, ceremony.threshold_n) do
                  {:ok, shares} ->
                    # Encrypt each share with custodian's password
                    shares_with_users =
                      custodian_passwords
                      |> Enum.with_index()
                      |> Enum.map(fn {{user_id, password}, idx} ->
                        share = Enum.at(shares, idx)
                        {:ok, encrypted} = ShareEncryption.encrypt_share(share, password)
                        {user_id, encrypted}
                      end)

                    # Update threshold_share records with encrypted data
                    Enum.each(shares_with_users, fn {user_id, encrypted_share} ->
                      share = repo.one!(
                        from s in ThresholdShare,
                          where: s.issuer_key_id == ^ceremony.issuer_key_id and
                                 s.custodian_user_id == ^user_id
                      )

                      share
                      |> Ecto.Changeset.change(%{encrypted_share: encrypted_share})
                      |> repo.update!()
                    end)

                    # Activate issuer key if root CA
                    if is_root and cert_der do
                      IssuerKeyManagement.activate_by_certificate(tenant_id, ceremony.issuer_key_id, cert_der, cert_pem)
                    end

                    # Update ceremony to completed
                    ceremony = repo.get!(KeyCeremony, ceremony_id)
                    ceremony
                    |> Ecto.Changeset.change(%{
                      status: "completed",
                      domain_info: Map.merge(ceremony.domain_info || %{}, %{
                        "fingerprint" => fingerprint,
                        "csr_pem" => csr_pem,
                        "subject_dn" => subject_dn
                      })
                    })
                    |> repo.update!()

                    # Wipe sensitive data
                    :erlang.garbage_collect()

                    {:ok, %{fingerprint: fingerprint, csr_pem: csr_pem}}

                  error ->
                    fail_ceremony(repo, ceremony_id, "shamir_split_failed")
                    error
                end

              error ->
                fail_ceremony(repo, ceremony_id, "cert_generation_failed")
                error
            end

          error ->
            fail_ceremony(repo, ceremony_id, "keygen_failed")
            error
        end

      {:ok, _} -> {:error, :invalid_status}
      error -> error
    end
  end

  @doc """
  Marks a ceremony as failed.
  """
  def fail_ceremony(tenant_id, ceremony_id, reason) when is_binary(tenant_id) do
    repo = TenantRepo.ca_repo(tenant_id)
    fail_ceremony(repo, ceremony_id, reason)
  end

  def fail_ceremony(repo, ceremony_id, reason) do
    case repo.get(KeyCeremony, ceremony_id) do
      nil -> {:error, :not_found}
      ceremony ->
        ceremony
        |> Ecto.Changeset.change(%{
          status: "failed",
          domain_info: Map.merge(ceremony.domain_info || %{}, %{"failure_reason" => reason})
        })
        |> repo.update()
    end
  end

  @doc """
  Lists attestations for a ceremony.
  """
  def list_attestations(tenant_id, ceremony_id) do
    repo = TenantRepo.ca_repo(tenant_id)
    repo.all(from a in CeremonyAttestation, where: a.ceremony_id == ^ceremony_id, order_by: [asc: a.attested_at])
  end

  # --- Private helpers ---

  defp get_ceremony(repo, ceremony_id) do
    case repo.get(KeyCeremony, ceremony_id) do
      nil -> {:error, :not_found}
      ceremony -> {:ok, ceremony}
    end
  end

  defp validate_threshold(k, n) when is_integer(k) and is_integer(n) and k >= 2 and k <= n, do: :ok
  defp validate_threshold(_, _), do: {:error, :invalid_threshold}

  defp validate_participants(user_ids, n) when length(user_ids) == n, do: :ok
  defp validate_participants(_, _), do: {:error, :participant_count_mismatch}

  defp generate_self_signed(private_key_der, subject_dn) do
    try do
      native_key = decode_private_key(private_key_der)
      root_cert = X509.Certificate.self_signed(native_key, subject_dn,
        template: :root_ca, hash: :sha256, serial: {:random, 8}, validity: 365 * 25)
      cert_der = X509.Certificate.to_der(root_cert)
      cert_pem = X509.Certificate.to_pem(root_cert)
      {:ok, cert_der, cert_pem}
    rescue
      e -> {:error, e}
    end
  end

  defp generate_csr(private_key_der, subject_dn) do
    try do
      native_key = decode_private_key(private_key_der)
      csr = X509.CSR.new(native_key, subject_dn)
      {:ok, X509.CSR.to_pem(csr)}
    rescue
      e -> {:error, e}
    end
  end

  defp decode_private_key(der) do
    try do
      :public_key.der_decode(:RSAPrivateKey, der)
    rescue
      _ -> :public_key.der_decode(:ECPrivateKey, der)
    end
  end
end
```

- [ ] **Step 2: Compile and verify**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_engine && mix compile
```

- [ ] **Step 3: Commit**

```bash
git add src/pki_ca_engine/lib/pki_ca_engine/ceremony_orchestrator.ex
git commit -m "feat(ca-engine): CeremonyOrchestrator — multi-participant phase transitions + atomic keygen"
```

---

### Task 4: CeremonyWatchdog (Time Window Enforcement)

**Files:**
- Create: `src/pki_ca_portal/lib/pki_ca_portal/ceremony_watchdog.ex`
- Modify: `src/pki_ca_portal/lib/pki_ca_portal/application.ex`

- [ ] **Step 1: Implement CeremonyWatchdog**

```elixir
# src/pki_ca_portal/lib/pki_ca_portal/ceremony_watchdog.ex
defmodule PkiCaPortal.CeremonyWatchdog do
  @moduledoc """
  Periodically checks for expired ceremonies and fails them.
  Runs every minute, checks window_expires_at on active ceremonies.
  """

  use GenServer
  require Logger

  alias PkiCaPortal.CaEngineClient
  alias PkiCaPortal.CustodianPasswordStore

  @check_interval_ms 60_000

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    schedule_check()
    {:ok, %{}}
  end

  @impl true
  def handle_info(:check_expired, state) do
    check_and_fail_expired()
    schedule_check()
    {:noreply, state}
  end

  defp check_and_fail_expired do
    # List all active ceremonies (preparing/generating status)
    # that have passed their window_expires_at
    case CaEngineClient.list_active_ceremonies() do
      {:ok, ceremonies} ->
        now = DateTime.utc_now()

        ceremonies
        |> Enum.filter(fn c ->
          c[:status] in ["preparing", "generating"] and
            c[:window_expires_at] != nil and
            DateTime.compare(now, c[:window_expires_at]) == :gt
        end)
        |> Enum.each(fn ceremony ->
          Logger.warning("[ceremony_watchdog] Expiring ceremony #{ceremony[:id]}")

          # Wipe passwords from ETS
          CustodianPasswordStore.wipe_ceremony(ceremony[:id])

          # Fail the ceremony in DB
          CaEngineClient.fail_ceremony(ceremony[:id], "window_expired")

          # Broadcast failure
          Phoenix.PubSub.broadcast(
            PkiCaPortal.PubSub,
            "ceremony:#{ceremony[:id]}",
            {:ceremony_failed, %{ceremony_id: ceremony[:id], reason: "window_expired"}}
          )

          # Audit log
          PkiPlatformEngine.PlatformAudit.log("ceremony_failed", %{
            portal: "ca",
            details: %{ceremony_id: ceremony[:id], reason: "window_expired"}
          })
        end)

      _ ->
        :ok
    end
  rescue
    e ->
      Logger.error("[ceremony_watchdog] Error checking expired ceremonies: #{inspect(e)}")
  end

  defp schedule_check do
    Process.send_after(self(), :check_expired, @check_interval_ms)
  end
end
```

- [ ] **Step 2: Add to supervision tree**

In `src/pki_ca_portal/lib/pki_ca_portal/application.ex`, add `PkiCaPortal.CeremonyWatchdog` to children after `CustodianPasswordStore`.

- [ ] **Step 3: Compile and commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_portal && mix compile
git add src/pki_ca_portal/lib/pki_ca_portal/ceremony_watchdog.ex \
        src/pki_ca_portal/lib/pki_ca_portal/application.ex
git commit -m "feat(ca-portal): CeremonyWatchdog — time window enforcement for ceremonies"
```

---

### Task 5: CeremonyNotifications (Async Email)

**Files:**
- Create: `src/pki_ca_portal/lib/pki_ca_portal/ceremony_notifications.ex`

- [ ] **Step 1: Implement CeremonyNotifications**

```elixir
# src/pki_ca_portal/lib/pki_ca_portal/ceremony_notifications.ex
defmodule PkiCaPortal.CeremonyNotifications do
  @moduledoc """
  Sends async email notifications for ceremony events.
  Uses Task.Supervisor for fire-and-forget delivery.
  """

  require Logger

  @task_supervisor PkiCaPortal.TaskSupervisor

  def notify_ceremony_initiated(ceremony, participants) do
    send_async(fn ->
      emails = resolve_emails(participants.custodian_user_ids ++ [participants.auditor_user_id])
      subject = "[PKI Ceremony] You've been assigned to Key Ceremony #{short_id(ceremony.id)}"
      body = ceremony_initiated_body(ceremony)
      send_to_all(emails, subject, body)
    end)
  end

  def notify_custodian_accepted(ceremony, custodian_username, ready_count, total_count) do
    send_async(fn ->
      admin_emails = resolve_admin_emails(ceremony.initiated_by)
      subject = "[PKI Ceremony] #{custodian_username} accepted share (#{ready_count}/#{total_count})"
      body = custodian_accepted_body(ceremony, custodian_username, ready_count, total_count)
      send_to_all(admin_emails, subject, body)
    end)
  end

  def notify_all_custodians_ready(ceremony) do
    send_async(fn ->
      auditor_emails = resolve_emails([ceremony.auditor_user_id])
      subject = "[PKI Ceremony] All custodians ready — please witness preparation"
      body = all_custodians_ready_body(ceremony)
      send_to_all(auditor_emails, subject, body)
    end)
  end

  def notify_witness_attested(ceremony, phase) do
    send_async(fn ->
      admin_emails = resolve_admin_emails(ceremony.initiated_by)
      subject = "[PKI Ceremony] Auditor witnessed #{phase} for Ceremony #{short_id(ceremony.id)}"
      body = witness_attested_body(ceremony, phase)
      send_to_all(admin_emails, subject, body)
    end)
  end

  def notify_ceremony_completed(ceremony, participants) do
    send_async(fn ->
      all_ids = participants.custodian_user_ids ++ [participants.auditor_user_id, ceremony.initiated_by]
      emails = resolve_emails(all_ids)
      subject = "[PKI Ceremony] Ceremony #{short_id(ceremony.id)} completed successfully"
      body = ceremony_completed_body(ceremony)
      send_to_all(emails, subject, body)
    end)
  end

  def notify_ceremony_failed(ceremony, reason, participants) do
    send_async(fn ->
      all_ids = participants.custodian_user_ids ++ [participants.auditor_user_id, ceremony.initiated_by]
      emails = resolve_emails(all_ids)
      subject = "[PKI Ceremony] Ceremony #{short_id(ceremony.id)} failed"
      body = ceremony_failed_body(ceremony, reason)
      send_to_all(emails, subject, body)
    end)
  end

  def notify_window_expiring(ceremony, pending_user_ids) do
    send_async(fn ->
      emails = resolve_emails(pending_user_ids)
      subject = "[PKI Ceremony] Ceremony #{short_id(ceremony.id)} expires in 1 hour"
      body = window_expiring_body(ceremony)
      send_to_all(emails, subject, body)
    end)
  end

  # --- Private ---

  defp send_async(fun) do
    Task.Supervisor.start_child(@task_supervisor, fun)
    :ok
  rescue
    e ->
      Logger.error("[ceremony_notifications] Failed to spawn notification task: #{inspect(e)}")
      :ok
  end

  defp send_to_all(emails, subject, body) do
    emails
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
    |> Enum.each(fn email ->
      PkiPlatformEngine.Mailer.send_email(email, subject, body)
    end)
  rescue
    e -> Logger.error("[ceremony_notifications] Failed to send emails: #{inspect(e)}")
  end

  defp resolve_emails(user_ids) do
    # Look up emails from platform admin list and CA user list
    admins = PkiPlatformEngine.AdminManagement.list_admins()
    admin_map = Map.new(admins, fn a -> {a.id, a.email} end)

    user_ids
    |> Enum.map(fn id -> admin_map[id] end)
    |> Enum.reject(&is_nil/1)
  rescue
    _ -> []
  end

  defp resolve_admin_emails(initiator_id) do
    resolve_emails([initiator_id])
  end

  defp short_id(id) when is_binary(id), do: String.slice(id, 0, 8)
  defp short_id(_), do: "unknown"

  defp ceremony_initiated_body(ceremony) do
    """
    <!DOCTYPE html><html><head><meta charset="utf-8"></head>
    <body style="font-family: sans-serif; padding: 20px;">
    <h2>Key Ceremony Assignment</h2>
    <p>You have been assigned to Key Ceremony <strong>#{short_id(ceremony.id)}</strong>.</p>
    <table style="border-collapse: collapse;">
    <tr><td style="padding: 4px 12px; font-weight: bold;">Algorithm</td><td>#{ceremony.algorithm}</td></tr>
    <tr><td style="padding: 4px 12px; font-weight: bold;">Threshold</td><td>#{ceremony.threshold_k}-of-#{ceremony.threshold_n}</td></tr>
    <tr><td style="padding: 4px 12px; font-weight: bold;">Deadline</td><td>#{ceremony.time_window_hours} hours</td></tr>
    </table>
    <p>Please log in to the CA Portal to complete your part.</p>
    <p style="color: #6b7280; font-size: 12px;">This is an automated notification from the PKI CA System.</p>
    </body></html>
    """
  end

  defp custodian_accepted_body(ceremony, username, ready, total) do
    """
    <!DOCTYPE html><html><head><meta charset="utf-8"></head>
    <body style="font-family: sans-serif; padding: 20px;">
    <h2>Custodian Share Accepted</h2>
    <p><strong>#{username}</strong> accepted their share for Ceremony <strong>#{short_id(ceremony.id)}</strong>.</p>
    <p>Progress: #{ready}/#{total} custodians ready.</p>
    </body></html>
    """
  end

  defp all_custodians_ready_body(ceremony) do
    """
    <!DOCTYPE html><html><head><meta charset="utf-8"></head>
    <body style="font-family: sans-serif; padding: 20px;">
    <h2>All Custodians Ready</h2>
    <p>All custodians have accepted their shares for Ceremony <strong>#{short_id(ceremony.id)}</strong>.</p>
    <p>Please log in to the CA Portal and witness the preparation phase.</p>
    </body></html>
    """
  end

  defp witness_attested_body(ceremony, phase) do
    """
    <!DOCTYPE html><html><head><meta charset="utf-8"></head>
    <body style="font-family: sans-serif; padding: 20px;">
    <h2>Auditor Witness</h2>
    <p>The auditor has witnessed the <strong>#{phase}</strong> phase for Ceremony <strong>#{short_id(ceremony.id)}</strong>.</p>
    </body></html>
    """
  end

  defp ceremony_completed_body(ceremony) do
    """
    <!DOCTYPE html><html><head><meta charset="utf-8"></head>
    <body style="font-family: sans-serif; padding: 20px;">
    <h2 style="color: #16a34a;">Ceremony Completed</h2>
    <p>Key Ceremony <strong>#{short_id(ceremony.id)}</strong> has been completed successfully.</p>
    <p>Algorithm: #{ceremony.algorithm} | Threshold: #{ceremony.threshold_k}-of-#{ceremony.threshold_n}</p>
    </body></html>
    """
  end

  defp ceremony_failed_body(ceremony, reason) do
    """
    <!DOCTYPE html><html><head><meta charset="utf-8"></head>
    <body style="font-family: sans-serif; padding: 20px;">
    <h2 style="color: #dc2626;">Ceremony Failed</h2>
    <p>Key Ceremony <strong>#{short_id(ceremony.id)}</strong> has failed.</p>
    <p>Reason: #{reason}</p>
    </body></html>
    """
  end

  defp window_expiring_body(ceremony) do
    """
    <!DOCTYPE html><html><head><meta charset="utf-8"></head>
    <body style="font-family: sans-serif; padding: 20px;">
    <h2 style="color: #d97706;">Ceremony Expiring Soon</h2>
    <p>Key Ceremony <strong>#{short_id(ceremony.id)}</strong> expires in approximately 1 hour.</p>
    <p>Please log in and complete your part before the deadline.</p>
    </body></html>
    """
  end
end
```

- [ ] **Step 2: Compile and commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_portal && mix compile
git add src/pki_ca_portal/lib/pki_ca_portal/ceremony_notifications.ex
git commit -m "feat(ca-portal): CeremonyNotifications — async email for ceremony events"
```

---

### Task 6: CaEngineClient Extensions + RBAC Update

**Files:**
- Modify: `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client.ex`
- Modify: `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/direct.ex`
- Modify: `src/pki_ca_portal/lib/pki_ca_portal_web/live/auth_hook.ex`
- Modify: `src/pki_ca_portal/lib/pki_ca_portal_web/router.ex`

- [ ] **Step 1: Add new functions to CaEngineClient behaviour**

In `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client.ex`, add these delegation functions:

```elixir
  # Ceremony orchestrator functions
  def initiate_witnessed_ceremony(ca_instance_id, params, opts \\ []), do: impl().initiate_witnessed_ceremony(ca_instance_id, params, opts)
  def accept_ceremony_share(ceremony_id, user_id, key_label, opts \\ []), do: impl().accept_ceremony_share(ceremony_id, user_id, key_label, opts)
  def attest_ceremony(ceremony_id, auditor_user_id, phase, details \\ %{}, opts \\ []), do: impl().attest_ceremony(ceremony_id, auditor_user_id, phase, details, opts)
  def check_ceremony_readiness(ceremony_id, opts \\ []), do: impl().check_ceremony_readiness(ceremony_id, opts)
  def execute_ceremony_keygen(ceremony_id, custodian_passwords, opts \\ []), do: impl().execute_ceremony_keygen(ceremony_id, custodian_passwords, opts)
  def fail_ceremony(ceremony_id, reason, opts \\ []), do: impl().fail_ceremony(ceremony_id, reason, opts)
  def list_ceremony_attestations(ceremony_id, opts \\ []), do: impl().list_ceremony_attestations(ceremony_id, opts)
  def list_active_ceremonies(opts \\ []), do: impl().list_active_ceremonies(opts)
  def list_my_ceremony_shares(user_id, opts \\ []), do: impl().list_my_ceremony_shares(user_id, opts)
  def list_my_witness_ceremonies(auditor_user_id, opts \\ []), do: impl().list_my_witness_ceremonies(auditor_user_id, opts)
```

- [ ] **Step 2: Implement in Direct client**

In `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/direct.ex`, add implementations that delegate to `PkiCaEngine.CeremonyOrchestrator`. Read the file first to understand the pattern (tenant_id extraction, error handling).

Each function follows the pattern:
```elixir
  def initiate_witnessed_ceremony(ca_instance_id, params, opts) do
    tenant_id = Keyword.get(opts, :tenant_id)
    PkiCaEngine.CeremonyOrchestrator.initiate(tenant_id, ca_instance_id, params)
  end
```

Implement all 10 functions following this pattern.

For `list_active_ceremonies`, `list_my_ceremony_shares`, and `list_my_witness_ceremonies`, add queries to the CeremonyOrchestrator or implement directly in the Direct client using Ecto queries.

- [ ] **Step 3: Update RBAC in auth_hook.ex**

In `src/pki_ca_portal/lib/pki_ca_portal_web/live/auth_hook.ex`, update `@role_pages`:

```elixir
  @role_pages %{
    "ca_admin" => :all,
    "key_manager" => [
      PkiCaPortalWeb.DashboardLive,
      PkiCaPortalWeb.CaInstancesLive,
      PkiCaPortalWeb.HsmDevicesLive,
      PkiCaPortalWeb.KeystoresLive,
      PkiCaPortalWeb.CeremonyCustodianLive,
      PkiCaPortalWeb.IssuerKeysLive,
      PkiCaPortalWeb.ProfileLive
    ],
    "auditor" => [
      PkiCaPortalWeb.DashboardLive,
      PkiCaPortalWeb.CaInstancesLive,
      PkiCaPortalWeb.AuditLogLive,
      PkiCaPortalWeb.CeremonyWitnessLive,
      PkiCaPortalWeb.ProfileLive
    ]
  }
```

Note: `CeremonyLive` removed from key_manager list, `CeremonyCustodianLive` added. `CeremonyWitnessLive` added to auditor list.

- [ ] **Step 4: Add routes**

In `src/pki_ca_portal/lib/pki_ca_portal_web/router.ex`, add inside the authenticated live_session:

```elixir
      live "/ceremony/custodian", CeremonyCustodianLive
      live "/ceremony/witness", CeremonyWitnessLive
```

- [ ] **Step 5: Compile and commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_portal && mix compile
git add src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client.ex \
        src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/direct.ex \
        src/pki_ca_portal/lib/pki_ca_portal_web/live/auth_hook.ex \
        src/pki_ca_portal/lib/pki_ca_portal_web/router.ex
git commit -m "feat(ca-portal): CaEngineClient extensions, RBAC update, ceremony routes"
```

---

### Task 7: CeremonyCustodianLive (Key Manager Share Acceptance Page)

**Files:**
- Create: `src/pki_ca_portal/lib/pki_ca_portal_web/live/ceremony_custodian_live.ex`

- [ ] **Step 1: Implement CeremonyCustodianLive**

This LiveView shows key managers their assigned ceremonies and lets them accept shares by entering a key label and password. It subscribes to PubSub for real-time ceremony updates.

Key features:
- Mount: load ceremonies where this user has pending/accepted shares via `CaEngineClient.list_my_ceremony_shares(user_id)`
- Subscribe to PubSub topic for each ceremony
- `handle_event("accept_share", ...)`: validate key_label (required) + password (min 8 chars, confirmation match), store password in `CustodianPasswordStore`, update share in DB via `CaEngineClient.accept_ceremony_share`, broadcast `custodian_ready` on PubSub, check if all custodians ready, send notification
- `handle_info` for PubSub events: update ceremony status in assigns
- Render: list of ceremonies with status badges, accept form for pending ones, live activity log

The page should include a live activity log section showing timestamped events for the selected ceremony.

- [ ] **Step 2: Compile and commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_portal && mix compile
git add src/pki_ca_portal/lib/pki_ca_portal_web/live/ceremony_custodian_live.ex
git commit -m "feat(ca-portal): CeremonyCustodianLive — key manager share acceptance page"
```

---

### Task 8: CeremonyWitnessLive (Auditor Witness Page)

**Files:**
- Create: `src/pki_ca_portal/lib/pki_ca_portal_web/live/ceremony_witness_live.ex`

- [ ] **Step 1: Implement CeremonyWitnessLive**

This LiveView shows auditors their assigned ceremonies and lets them witness each phase gate. It subscribes to PubSub for real-time ceremony updates.

Key features:
- Mount: load ceremonies where this user is assigned auditor via `CaEngineClient.list_my_witness_ceremonies(user_id)`
- Subscribe to PubSub topic for each ceremony
- `handle_event("witness_phase", %{"phase" => phase, "password" => password})`: verify auditor password (re-authenticate via `CaEngineClient.authenticate_with_session`), create attestation via `CaEngineClient.attest_ceremony`, broadcast `witness_attested` on PubSub, send notification, check if ceremony can proceed to keygen
- After preparation witness + all custodians ready: trigger `execute_ceremony_keygen` (fetch passwords from CustodianPasswordStore, call orchestrator, wipe passwords)
- After key_generation witness: notify for final witness
- After completion witness: ceremony fully attested
- Render: list of ceremonies, witness view with full ceremony log, phase details, "I Witness" button with password input

The witness view should show:
- Preparation phase: participant list (who accepted, when, with key labels)
- Key generation phase: fingerprint, algorithm, share count
- Completion phase: certificate/CSR details, full ceremony log

- [ ] **Step 2: Compile and commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_portal && mix compile
git add src/pki_ca_portal/lib/pki_ca_portal_web/live/ceremony_witness_live.ex
git commit -m "feat(ca-portal): CeremonyWitnessLive — auditor witness page"
```

---

### Task 9: Modify CeremonyLive (Admin Initiation + Progress Dashboard)

**Files:**
- Modify: `src/pki_ca_portal/lib/pki_ca_portal_web/live/ceremony_live.ex`

- [ ] **Step 1: Modify ceremony initiation**

The existing CeremonyLive is 1,133 lines with a 4-step wizard. Replace the wizard with:

**Initiation form (replaces old step 1):**
- Keep existing fields: algorithm, keystore, key alias, cert type, threshold k/n
- Add: key manager multi-select (from users with key_manager role)
- Add: auditor select (from users with auditor role)
- Add: time window selector (hours, default 24)
- On submit: call `CaEngineClient.initiate_witnessed_ceremony` instead of the old `initiate_ceremony`
- Send notification via `CeremonyNotifications.notify_ceremony_initiated`
- Subscribe to PubSub topic for the new ceremony

**Progress dashboard (replaces old steps 2-4):**
- After initiation, show a progress view instead of the wizard
- Participant status table: name, role, status (pending/ready/witnessed), timestamp
- Time remaining countdown
- Live activity log (PubSub events)
- Cancel button (calls `CaEngineClient.fail_ceremony`, wipes ETS, broadcasts failure)

**Remove:** The old wizard steps 2-4 (generate_keypair, distribute_shares, complete_ceremony event handlers). These are now handled by the orchestrator + custodian/witness pages.

**Keep:** The ceremony list view, pagination, resume/delete actions.

- [ ] **Step 2: Compile and commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_portal && mix compile
git add src/pki_ca_portal/lib/pki_ca_portal_web/live/ceremony_live.ex
git commit -m "feat(ca-portal): CeremonyLive — admin initiation form + progress dashboard"
```

---

### Task 10: Sidebar Navigation Updates

**Files:**
- Modify: `src/pki_ca_portal/lib/pki_ca_portal_web/components/layouts.ex`

- [ ] **Step 1: Add ceremony custodian/witness nav links**

In the sidebar navigation of the `app/1` function, add role-conditional links:

```heex
<.sidebar_link :if={role in ["ca_admin", "key_manager"]} href="/ceremony/custodian" icon="hero-key" label="My Shares" current={@page_title} />
<.sidebar_link :if={role in ["ca_admin", "auditor"]} href="/ceremony/witness" icon="hero-eye" label="Witness" current={@page_title} />
```

Update `is_active?/2` to include the new pages:
```elixir
defp is_active?("My Shares", "My Ceremony Shares"), do: true
defp is_active?("Witness", "Ceremony Witness"), do: true
```

- [ ] **Step 2: Compile and commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_portal && mix compile
git add src/pki_ca_portal/lib/pki_ca_portal_web/components/layouts.ex
git commit -m "feat(ca-portal): add ceremony custodian and witness sidebar navigation"
```

---

### Task 11: Integration Verification

- [ ] **Step 1: Compile all projects**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_engine && mix compile
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_portal && mix compile
```

- [ ] **Step 2: Run existing tests to verify nothing broke**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_portal && MIX_ENV=test elixir --sname test_ceremony -S mix test test/pki_ca_portal/custodian_password_store_test.exs --trace
```

- [ ] **Step 3: Run DB migration on test DB**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_engine && MIX_ENV=test mix ecto.migrate
```
