# API Key Management & Service Config Redesign — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Redesign API Key Management into production-grade access control with per-key rate limiting, IP whitelist, key types, cert profile restrictions, webhook notifications, and auto-approve flow for cert profiles.

**Architecture:** Four phases — (A) schema migrations and data layer, (B) engine enforcement plugs and auto-approve, (C) webhook delivery system, (D) portal UI redesign. Each phase produces working, testable code. All enforcement happens at the engine API boundary, not in the portal.

**Tech Stack:** Elixir, Ecto, Phoenix LiveView, Plug, Hammer (rate limiting), Req (webhook HTTP), DaisyUI/Tailwind (portal UI)

---

## File Structure

### RA Engine — New Files
```
lib/pki_ra_engine/api/api_key_scope_plug.ex        — key type permission enforcement
lib/pki_ra_engine/api/ip_whitelist_plug.ex          — per-key IP whitelist check
lib/pki_ra_engine/webhook_delivery.ex               — webhook dispatch + retry
priv/repo/migrations/20260405100001_enhance_api_keys.exs
priv/repo/migrations/20260405100002_add_approval_mode_to_cert_profiles.exs
priv/repo/migrations/20260405100003_add_submitted_by_key_to_csr_requests.exs
priv/repo/migrations/20260405100004_simplify_service_configs.exs
test/pki_ra_engine/api_key_enforcement_test.exs     — per-key rate limit, IP, scope tests
test/pki_ra_engine/webhook_delivery_test.exs
test/pki_ra_engine/auto_approve_test.exs
```

### RA Engine — Modified Files
```
lib/pki_ra_engine/schema/ra_api_key.ex              — new fields
lib/pki_ra_engine/schema/cert_profile.ex            — approval_mode
lib/pki_ra_engine/schema/csr_request.ex             — submitted_by_key_id
lib/pki_ra_engine/schema/service_config.ex          — simplified, add status
lib/pki_ra_engine/api_key_management.ex             — profile restriction validation
lib/pki_ra_engine/api/auth_plug.ex                  — per-key rate limiting + IP check
lib/pki_ra_engine/api/authenticated_router.ex       — scope plug wiring
lib/pki_ra_engine/csr_validation.ex                 — auto-approve flow, submitted_by_key_id
lib/pki_ra_engine/api/csr_controller.ex             — pass submitted_by_key_id
lib/pki_ra_engine/service_config.ex                 — normalize types, add status
lib/pki_ra_engine/application.ex                    — (no change needed, Task.Supervisor already exists)
```

### RA Portal — Modified Files
```
lib/pki_ra_portal_web/live/api_keys_live.ex         — full form redesign
lib/pki_ra_portal_web/live/service_configs_live.ex   — simplified, renamed
lib/pki_ra_portal_web/live/cert_profiles_live.ex     — approval_mode toggle
lib/pki_ra_portal_web/components/layouts.ex          — rename sidebar item
lib/pki_ra_portal/ra_engine_client.ex               — new callbacks
lib/pki_ra_portal/ra_engine_client/direct.ex        — implement new functions
```

### Platform Engine — Modified Files
```
lib/pki_platform_engine/platform_audit_event.ex     — register new actions
```

---

## Phase A: Schema Migrations & Data Layer

### Task 1: Enhance API Key Schema

**Files:**
- Create: `src/pki_ra_engine/priv/repo/migrations/20260405100001_enhance_api_keys.exs`
- Modify: `src/pki_ra_engine/lib/pki_ra_engine/schema/ra_api_key.ex`
- Test: `src/pki_ra_engine/test/pki_ra_engine/api_key_management_test.exs`

- [ ] **Step 1: Write the migration**

```elixir
defmodule PkiRaEngine.Repo.Migrations.EnhanceApiKeys do
  use Ecto.Migration

  def change do
    alter table(:ra_api_keys) do
      add :key_type, :string, default: "client", null: false
      add :allowed_profile_ids, :jsonb, default: "[]"
      add :ip_whitelist, :jsonb, default: "[]"
      add :webhook_url, :string
      add :webhook_secret, :string
    end

    create index(:ra_api_keys, [:key_type])
  end
end
```

- [ ] **Step 2: Update the RaApiKey schema**

Add to `ra_api_key.ex`:
- `@key_types ["client", "service"]`
- Fields: `key_type`, `allowed_profile_ids` (as `{:array, :string}`), `ip_whitelist` (as `{:array, :string}`), `webhook_url`, `webhook_secret`
- Add `key_type` to `@required_fields`
- Add new fields to `@optional_fields`
- Add `validate_inclusion(:key_type, @key_types)`
- Add `validate_length(:label, max: 100)`
- Add validation: `allowed_profile_ids` must not be empty (custom validation)

```elixir
@key_types ["client", "service"]
@statuses ["active", "revoked"]

schema "ra_api_keys" do
  field :hashed_key, :string
  field :label, :string
  field :key_type, :string, default: "client"
  field :expiry, :utc_datetime_usec
  field :rate_limit, :integer, default: 60
  field :status, :string, default: "active"
  field :revoked_at, :utc_datetime_usec
  field :allowed_profile_ids, {:array, :string}, default: []
  field :ip_whitelist, {:array, :string}, default: []
  field :webhook_url, :string
  field :webhook_secret, :string

  belongs_to :ra_user, PkiRaEngine.Schema.RaUser
  belongs_to :ra_instance, PkiRaEngine.Schema.RaInstance

  timestamps()
end

@required_fields [:hashed_key, :ra_user_id, :key_type, :expiry]
@optional_fields [
  :label, :rate_limit, :status, :revoked_at, :ra_instance_id,
  :allowed_profile_ids, :ip_whitelist, :webhook_url, :webhook_secret
]

def changeset(api_key, attrs) do
  api_key
  |> cast(attrs, @required_fields ++ @optional_fields)
  |> validate_required(@required_fields)
  |> validate_inclusion(:status, @statuses)
  |> validate_inclusion(:key_type, @key_types)
  |> validate_length(:label, max: 100)
  |> validate_rate_limit()
  |> foreign_key_constraint(:ra_user_id)
  |> maybe_generate_id()
end

defp validate_rate_limit(changeset) do
  case get_field(changeset, :rate_limit) do
    nil -> changeset
    rl when rl >= 1 and rl <= 10000 -> changeset
    _ -> add_error(changeset, :rate_limit, "must be between 1 and 10000")
  end
end
```

- [ ] **Step 3: Update ApiKeyManagement.create_api_key to accept new fields**

In `api_key_management.ex`, update `create_api_key/2` to pass through the new fields from `attrs` and auto-generate `webhook_secret` when `webhook_url` is present:

```elixir
def create_api_key(tenant_id, attrs) do
  repo = TenantRepo.ra_repo(tenant_id)
  raw_key = :crypto.strong_rand_bytes(32)
  hashed = hash_key(raw_key)

  # Auto-generate webhook secret if webhook_url is provided
  webhook_url = attrs[:webhook_url] || attrs["webhook_url"]
  webhook_secret = if webhook_url && webhook_url != "" do
    :crypto.strong_rand_bytes(32) |> Base.encode64(padding: false)
  else
    nil
  end

  api_key_attrs =
    attrs
    |> Map.put(:hashed_key, hashed)
    |> Map.put(:webhook_secret, webhook_secret)

  case %RaApiKey{} |> RaApiKey.changeset(api_key_attrs) |> repo.insert() do
    {:ok, api_key} ->
      audit("api_key_created", tenant_id, "api_key", api_key.id, %{
        ra_user_id: api_key.ra_user_id,
        label: api_key.label,
        key_type: api_key.key_type
      })
      {:ok, %{raw_key: Base.encode64(raw_key), api_key: api_key, webhook_secret: webhook_secret}}

    {:error, changeset} ->
      {:error, changeset}
  end
end
```

- [ ] **Step 4: Run migration and compile**

```bash
cd src/pki_ra_engine && MIX_ENV=test mix ecto.migrate && mix compile
```

- [ ] **Step 5: Run existing tests to verify no regressions**

```bash
mix test test/pki_ra_engine/api_key_management_test.exs
```
Expected: All pass (new fields have defaults)

- [ ] **Step 6: Commit**

```bash
git add src/pki_ra_engine/priv/repo/migrations/20260405100001_enhance_api_keys.exs \
        src/pki_ra_engine/lib/pki_ra_engine/schema/ra_api_key.ex \
        src/pki_ra_engine/lib/pki_ra_engine/api_key_management.ex
git commit -m "feat(ra-engine): enhance API key schema — key types, IP whitelist, webhooks"
```

---

### Task 2: Add approval_mode to Cert Profiles

**Files:**
- Create: `src/pki_ra_engine/priv/repo/migrations/20260405100002_add_approval_mode_to_cert_profiles.exs`
- Modify: `src/pki_ra_engine/lib/pki_ra_engine/schema/cert_profile.ex`

- [ ] **Step 1: Write the migration**

```elixir
defmodule PkiRaEngine.Repo.Migrations.AddApprovalModeToCertProfiles do
  use Ecto.Migration

  def change do
    alter table(:cert_profiles) do
      add :approval_mode, :string, default: "manual", null: false
    end
  end
end
```

- [ ] **Step 2: Update CertProfile schema**

Add to `cert_profile.ex`:
- `@approval_modes ["auto", "manual"]`
- `field :approval_mode, :string, default: "manual"`
- Add `:approval_mode` to `@optional_fields`
- Add `validate_inclusion(:approval_mode, @approval_modes)` to changeset

- [ ] **Step 3: Run migration, compile, run cert profile tests**

```bash
MIX_ENV=test mix ecto.migrate && mix compile
mix test test/pki_ra_engine/cert_profile_config_test.exs
```

- [ ] **Step 4: Commit**

```bash
git add src/pki_ra_engine/priv/repo/migrations/20260405100002_add_approval_mode_to_cert_profiles.exs \
        src/pki_ra_engine/lib/pki_ra_engine/schema/cert_profile.ex
git commit -m "feat(ra-engine): add approval_mode to cert profiles (auto/manual)"
```

---

### Task 3: Add submitted_by_key_id to CSR Requests

**Files:**
- Create: `src/pki_ra_engine/priv/repo/migrations/20260405100003_add_submitted_by_key_to_csr_requests.exs`
- Modify: `src/pki_ra_engine/lib/pki_ra_engine/schema/csr_request.ex`
- Modify: `src/pki_ra_engine/lib/pki_ra_engine/api/csr_controller.ex`

- [ ] **Step 1: Write the migration**

```elixir
defmodule PkiRaEngine.Repo.Migrations.AddSubmittedByKeyToCsrRequests do
  use Ecto.Migration

  def change do
    alter table(:csr_requests) do
      add :submitted_by_key_id, :binary_id
    end

    create index(:csr_requests, [:submitted_by_key_id])
  end
end
```

- [ ] **Step 2: Update CsrRequest schema**

Add `field :submitted_by_key_id, :binary_id` to the schema and `:submitted_by_key_id` to `@optional_fields`.

- [ ] **Step 3: Update CsrController.submit to record the API key**

In `csr_controller.ex`, inside the `submit/1` function, after `fetch_param` calls, add:

```elixir
submitted_by_key_id = case conn.assigns do
  %{auth_type: :api_key, current_api_key: api_key} -> api_key.id
  _ -> nil
end
```

Pass `submitted_by_key_id` through to `CsrValidation.submit_csr` — this requires updating `submit_csr` to accept an optional `opts` keyword with `:submitted_by_key_id`.

- [ ] **Step 4: Update CsrValidation.submit_csr to accept and store submitted_by_key_id**

Add an optional fourth parameter `opts \\ []`:

```elixir
def submit_csr(tenant_id, csr_pem, cert_profile_id, opts \\ []) do
  repo = TenantRepo.ra_repo(tenant_id)
  subject_dn = extract_subject_dn(csr_pem)
  submitted_by_key_id = Keyword.get(opts, :submitted_by_key_id)

  attrs = %{
    csr_pem: csr_pem,
    cert_profile_id: cert_profile_id,
    subject_dn: subject_dn,
    status: "pending",
    submitted_at: DateTime.utc_now(),
    submitted_by_key_id: submitted_by_key_id
  }
  # ... rest unchanged
end
```

- [ ] **Step 5: Run migration, compile, run all CSR tests**

```bash
MIX_ENV=test mix ecto.migrate && mix compile
mix test test/pki_ra_engine/csr_validation_test.exs test/pki_ra_engine/api/csr_controller_test.exs
```

- [ ] **Step 6: Commit**

```bash
git add src/pki_ra_engine/priv/repo/migrations/20260405100003_add_submitted_by_key_to_csr_requests.exs \
        src/pki_ra_engine/lib/pki_ra_engine/schema/csr_request.ex \
        src/pki_ra_engine/lib/pki_ra_engine/api/csr_controller.ex \
        src/pki_ra_engine/lib/pki_ra_engine/csr_validation.ex
git commit -m "feat(ra-engine): track submitted_by_key_id on CSR requests"
```

---

### Task 4: Simplify Service Configs

**Files:**
- Create: `src/pki_ra_engine/priv/repo/migrations/20260405100004_simplify_service_configs.exs`
- Modify: `src/pki_ra_engine/lib/pki_ra_engine/schema/service_config.ex`
- Modify: `src/pki_ra_engine/lib/pki_ra_engine/service_config.ex`

- [ ] **Step 1: Write the migration**

```elixir
defmodule PkiRaEngine.Repo.Migrations.SimplifyServiceConfigs do
  use Ecto.Migration

  def change do
    alter table(:service_configs) do
      add_if_not_exists :status, :string, default: "active", null: false
    end

    # Normalize existing service_type values
    execute "UPDATE service_configs SET service_type = 'ocsp_responder' WHERE service_type IN ('OCSP Responder', 'ocsp')", ""
    execute "UPDATE service_configs SET service_type = 'crl_distribution' WHERE service_type IN ('CRL Distribution', 'crl')", ""
    execute "UPDATE service_configs SET service_type = 'tsa' WHERE service_type IN ('TSA')", ""
  end
end
```

- [ ] **Step 2: Update ServiceConfig schema**

Update `@service_types` to normalized values:
```elixir
@service_types ["ocsp_responder", "crl_distribution", "tsa"]
@statuses ["active", "inactive"]
```

Add `field :status, :string, default: "active"` and `:status` to optional fields. Add `validate_inclusion(:status, @statuses)`.

- [ ] **Step 3: Run migration, compile, run service config tests**

```bash
MIX_ENV=test mix ecto.migrate && mix compile
mix test test/pki_ra_engine/service_config_test.exs
```
Note: Tests may need updating if they use old service_type values.

- [ ] **Step 4: Commit**

```bash
git add src/pki_ra_engine/priv/repo/migrations/20260405100004_simplify_service_configs.exs \
        src/pki_ra_engine/lib/pki_ra_engine/schema/service_config.ex \
        src/pki_ra_engine/lib/pki_ra_engine/service_config.ex
git commit -m "feat(ra-engine): simplify service configs — normalize types, add status"
```

---

### Task 5: Register New Audit Actions

**Files:**
- Modify: `src/pki_platform_engine/lib/pki_platform_engine/platform_audit_event.ex`

- [ ] **Step 1: Add new audit actions**

Add to `@actions`:
```
webhook_delivered webhook_failed
api_key_rate_limited api_key_ip_rejected api_key_scope_denied
```

Add to `@system_actions`:
```
webhook_delivered webhook_failed
api_key_rate_limited api_key_ip_rejected api_key_scope_denied
```

- [ ] **Step 2: Compile**

```bash
mix compile
```

- [ ] **Step 3: Commit**

```bash
git add src/pki_platform_engine/lib/pki_platform_engine/platform_audit_event.ex
git commit -m "feat(platform): register webhook and API key enforcement audit actions"
```

---

## Phase B: Engine Enforcement

### Task 6: Per-Key Rate Limiting in AuthPlug

**Files:**
- Modify: `src/pki_ra_engine/lib/pki_ra_engine/api/auth_plug.ex`

- [ ] **Step 1: Add per-key rate limiting after successful API key auth**

In `auth_plug.ex`, after `ApiKeyManagement.verify_key` returns `{:ok, api_key}`, add rate limiting check before proceeding:

```elixir
{:ok, api_key} ->
  # Per-key rate limiting
  rate_limit = api_key.rate_limit || 60
  rate_key = "api_key:#{api_key.id}"

  case Hammer.check_rate(rate_key, 60_000, rate_limit) do
    {:allow, _count} ->
      Logger.metadata(...)
      conn |> assign(...) # existing code

    {:deny, _limit} ->
      audit_rate_limited(api_key, tenant_id, conn)
      conn
      |> put_resp_content_type("application/json")
      |> put_resp_header("retry-after", "60")
      |> send_resp(429, Jason.encode!(%{
        error: "rate_limited",
        retry_after: 60,
        limit: rate_limit,
        message: "Rate limit exceeded. Try again in 60 seconds."
      }))
      |> halt()

    {:error, _} ->
      # Hammer error — allow through (fail open for availability)
      Logger.metadata(...)
      conn |> assign(...) # existing code
  end
```

Add `audit_rate_limited/3` private function that logs to PlatformAudit.

- [ ] **Step 2: Compile and run auth plug tests**

```bash
mix compile && mix test test/pki_ra_engine/api/auth_plug_test.exs
```

- [ ] **Step 3: Commit**

```bash
git add src/pki_ra_engine/lib/pki_ra_engine/api/auth_plug.ex
git commit -m "feat(ra-engine): per-key rate limiting in AuthPlug"
```

---

### Task 7: IP Whitelist Enforcement

**Files:**
- Create: `src/pki_ra_engine/lib/pki_ra_engine/api/ip_whitelist_plug.ex`
- Modify: `src/pki_ra_engine/lib/pki_ra_engine/api/auth_plug.ex`

- [ ] **Step 1: Create IpWhitelistPlug**

```elixir
defmodule PkiRaEngine.Api.IpWhitelistPlug do
  @moduledoc "Checks client IP against API key's ip_whitelist. Empty whitelist = allow all."

  import Plug.Conn
  require Logger

  def check(conn, %{ip_whitelist: []} = _api_key), do: conn
  def check(conn, %{ip_whitelist: nil} = _api_key), do: conn

  def check(conn, api_key) do
    client_ip = client_ip_string(conn)

    if ip_in_whitelist?(client_ip, api_key.ip_whitelist) do
      conn
    else
      audit_ip_rejected(api_key, client_ip, conn.assigns[:tenant_id])

      conn
      |> put_resp_content_type("application/json")
      |> send_resp(403, Jason.encode!(%{
        error: "ip_not_allowed",
        message: "Request from this IP address is not permitted."
      }))
      |> halt()
    end
  end

  defp client_ip_string(conn) do
    conn.remote_ip |> :inet.ntoa() |> to_string()
  end

  defp ip_in_whitelist?(ip, whitelist) do
    Enum.any?(whitelist, fn cidr ->
      case parse_cidr(cidr) do
        {:ok, network, mask} -> ip_in_network?(ip, network, mask)
        :error -> ip == cidr  # Fallback to exact match
      end
    end)
  end

  defp parse_cidr(cidr) do
    case String.split(cidr, "/") do
      [ip_str, mask_str] ->
        with {:ok, ip} <- :inet.parse_address(String.to_charlist(ip_str)),
             {mask, ""} <- Integer.parse(mask_str) do
          {:ok, ip, mask}
        else
          _ -> :error
        end
      [ip_str] ->
        case :inet.parse_address(String.to_charlist(ip_str)) do
          {:ok, ip} -> {:ok, ip, if(tuple_size(ip) == 4, do: 32, else: 128)}
          _ -> :error
        end
    end
  end

  defp ip_in_network?(ip_str, network, mask) do
    case :inet.parse_address(String.to_charlist(ip_str)) do
      {:ok, ip} ->
        ip_int = ip_to_integer(ip)
        net_int = ip_to_integer(network)
        bits = if tuple_size(network) == 4, do: 32, else: 128
        shift = bits - mask
        Bitwise.bsr(ip_int, shift) == Bitwise.bsr(net_int, shift)
      _ -> false
    end
  end

  defp ip_to_integer({a, b, c, d}), do: Bitwise.bsl(a, 24) + Bitwise.bsl(b, 16) + Bitwise.bsl(c, 8) + d
  defp ip_to_integer(ipv6) when tuple_size(ipv6) == 8 do
    ipv6 |> Tuple.to_list() |> Enum.reduce(0, fn seg, acc -> Bitwise.bsl(acc, 16) + seg end)
  end

  defp audit_ip_rejected(api_key, client_ip, tenant_id) do
    PkiPlatformEngine.PlatformAudit.log("api_key_ip_rejected", %{
      target_type: "api_key",
      target_id: api_key.id,
      tenant_id: tenant_id,
      portal: "ra",
      details: %{ip: client_ip, whitelist: api_key.ip_whitelist}
    })
  rescue
    _ -> :ok
  end
end
```

- [ ] **Step 2: Wire IP check into AuthPlug after rate limit check**

In `auth_plug.ex`, after the rate limit check passes, add:

```elixir
conn = PkiRaEngine.Api.IpWhitelistPlug.check(conn, api_key)
if conn.halted, do: conn, else: # proceed with assigns
```

- [ ] **Step 3: Compile**

```bash
mix compile
```

- [ ] **Step 4: Commit**

```bash
git add src/pki_ra_engine/lib/pki_ra_engine/api/ip_whitelist_plug.ex \
        src/pki_ra_engine/lib/pki_ra_engine/api/auth_plug.ex
git commit -m "feat(ra-engine): per-key IP whitelist enforcement"
```

---

### Task 8: Key Type Scope Enforcement

**Files:**
- Create: `src/pki_ra_engine/lib/pki_ra_engine/api/api_key_scope_plug.ex`
- Modify: `src/pki_ra_engine/lib/pki_ra_engine/api/authenticated_router.ex`

- [ ] **Step 1: Create ApiKeyScopePlug**

```elixir
defmodule PkiRaEngine.Api.ApiKeyScopePlug do
  @moduledoc """
  Enforces API key type permissions on routes.
  Internal callers bypass scope checks.
  Client keys: submit_csr, view own CSRs/certs only.
  Service keys: client permissions + revoke.
  """

  import Plug.Conn

  @client_permissions [:submit_csr, :view_csr, :view_certificates]
  @service_permissions @client_permissions ++ [:revoke_certificate, :manage_dcv]

  def init(permission), do: permission

  def call(%{assigns: %{auth_type: :internal}} = conn, _permission), do: conn

  def call(%{assigns: %{auth_type: :api_key, current_api_key: api_key}} = conn, permission) do
    allowed = case api_key.key_type do
      "service" -> @service_permissions
      "client" -> @client_permissions
      _ -> []
    end

    if permission in allowed do
      conn
    else
      audit_scope_denied(api_key, permission, conn.assigns[:tenant_id])

      conn
      |> put_resp_content_type("application/json")
      |> send_resp(403, Jason.encode!(%{error: "scope_denied", message: "This API key does not have permission for this operation."}))
      |> halt()
    end
  end

  def call(conn, _permission), do: conn

  defp audit_scope_denied(api_key, permission, tenant_id) do
    PkiPlatformEngine.PlatformAudit.log("api_key_scope_denied", %{
      target_type: "api_key",
      target_id: api_key.id,
      tenant_id: tenant_id,
      portal: "ra",
      details: %{permission: to_string(permission), key_type: api_key.key_type}
    })
  rescue
    _ -> :ok
  end
end
```

- [ ] **Step 2: Wire scope checks into authenticated_router.ex**

After the existing `RbacPlug` calls, add `ApiKeyScopePlug` checks for API-key-relevant routes. The scope plug runs AFTER RBAC (RBAC handles role-based auth for human users, scope handles key-type auth for API keys):

```elixir
# CSR routes — add scope check
post "/csr" do
  conn
  |> RbacPlug.call(:process_csrs)
  |> ApiKeyScopePlug.call(:submit_csr)
  |> dispatch_unless_halted(&CsrController.submit/1)
end

# Certificate revoke — service keys only
post "/certificates/:serial/revoke" do
  conn
  |> RbacPlug.call(:process_csrs)
  |> ApiKeyScopePlug.call(:revoke_certificate)
  |> dispatch_unless_halted(&CertController.revoke(&1, serial))
end
```

- [ ] **Step 3: Compile**

```bash
mix compile
```

- [ ] **Step 4: Commit**

```bash
git add src/pki_ra_engine/lib/pki_ra_engine/api/api_key_scope_plug.ex \
        src/pki_ra_engine/lib/pki_ra_engine/api/authenticated_router.ex
git commit -m "feat(ra-engine): API key type scope enforcement (client/service)"
```

---

### Task 9: Cert Profile Allowed Check on CSR Submit

**Files:**
- Modify: `src/pki_ra_engine/lib/pki_ra_engine/api/csr_controller.ex`

- [ ] **Step 1: Add allowed profile check in CsrController.submit**

After validating params but before calling `CsrValidation.submit_csr`, check if the API key is allowed to submit against this profile:

```elixir
# In submit/1, after fetch_param calls:
case conn.assigns do
  %{auth_type: :api_key, current_api_key: api_key} ->
    allowed = api_key.allowed_profile_ids || []
    if allowed != [] and cert_profile_id not in allowed do
      json_resp(conn, 403, %{error: "profile_not_allowed", message: "This API key is not authorized for this certificate profile."})
    else
      # proceed with submit_csr
    end

  _ ->
    # Internal/portal caller — no profile restriction
    # proceed with submit_csr
end
```

- [ ] **Step 2: Compile and run tests**

```bash
mix compile && mix test test/pki_ra_engine/api/csr_controller_test.exs
```

- [ ] **Step 3: Commit**

```bash
git add src/pki_ra_engine/lib/pki_ra_engine/api/csr_controller.ex
git commit -m "feat(ra-engine): enforce allowed_profile_ids on CSR submission"
```

---

### Task 10: Auto-Approve Flow

**Files:**
- Modify: `src/pki_ra_engine/lib/pki_ra_engine/csr_validation.ex`
- Create: `src/pki_ra_engine/test/pki_ra_engine/auto_approve_test.exs`

- [ ] **Step 1: Write auto-approve test**

```elixir
defmodule PkiRaEngine.AutoApproveTest do
  use PkiRaEngine.DataCase, async: false

  alias PkiRaEngine.CsrValidation
  alias PkiRaEngine.CertProfileConfig

  setup do
    Application.put_env(:pki_ra_engine, :ca_engine_module, PkiRaEngine.Test.CaEngineStub)
    on_exit(fn -> Application.delete_env(:pki_ra_engine, :ca_engine_module) end)
    :ok
  end

  test "auto-approve profile: validation pass auto-forwards to CA" do
    {:ok, profile} = CertProfileConfig.create_profile(nil, %{
      name: "auto_profile_#{System.unique_integer([:positive])}",
      approval_mode: "auto"
    })

    csr_pem = "-----BEGIN CERTIFICATE REQUEST-----\nMIIBauto\n-----END CERTIFICATE REQUEST-----"
    {:ok, csr} = CsrValidation.submit_csr(nil, csr_pem, profile.id)
    assert csr.status == "pending"

    {:ok, validated} = CsrValidation.validate_csr(nil, csr.id)

    # Auto-approve should trigger: verified → approved → issued (via CA stub)
    # Wait for async task
    Process.sleep(200)

    {:ok, final} = CsrValidation.get_csr(nil, csr.id)
    assert final.status in ["approved", "issued"]
  end

  test "manual profile: validation does NOT auto-forward" do
    {:ok, profile} = CertProfileConfig.create_profile(nil, %{
      name: "manual_profile_#{System.unique_integer([:positive])}",
      approval_mode: "manual"
    })

    csr_pem = "-----BEGIN CERTIFICATE REQUEST-----\nMIIBmanual\n-----END CERTIFICATE REQUEST-----"
    {:ok, csr} = CsrValidation.submit_csr(nil, csr_pem, profile.id)
    {:ok, validated} = CsrValidation.validate_csr(nil, csr.id)

    assert validated.status == "verified"

    # Should NOT auto-forward
    Process.sleep(200)
    {:ok, still_verified} = CsrValidation.get_csr(nil, csr.id)
    assert still_verified.status == "verified"
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

```bash
mix test test/pki_ra_engine/auto_approve_test.exs
```
Expected: First test fails (auto-approve not implemented yet)

- [ ] **Step 3: Implement auto-approve in validate_csr**

In `csr_validation.ex`, inside `validate_csr/2`, after successful validation transitions to `"verified"`, check the profile's `approval_mode`:

```elixir
def validate_csr(tenant_id, csr_id) do
  repo = TenantRepo.ra_repo(tenant_id)

  with {:ok, csr} <- get_csr(tenant_id, csr_id),
       :ok <- check_auto_transition(csr.status, "verified") do
    case run_validations(tenant_id, csr) do
      :ok ->
        {:ok, verified} = transition(repo, csr, "verified", %{})

        # Check for auto-approve
        maybe_auto_approve(tenant_id, verified)

        {:ok, verified}

      {:error, _reason} ->
        transition(repo, csr, "rejected", %{})
    end
  end
end

defp maybe_auto_approve(tenant_id, csr) do
  case CertProfileConfig.get_profile(tenant_id, csr.cert_profile_id) do
    {:ok, %{approval_mode: "auto"} = profile} ->
      # Check DCV requirement
      dcv_ok = case check_dcv_requirement(tenant_id, csr) do
        :ok -> true
        _ -> false
      end

      if dcv_ok do
        Task.Supervisor.start_child(PkiRaEngine.TaskSupervisor, fn ->
          # Auto-approve: transition verified → approved → issued
          repo = TenantRepo.ra_repo(tenant_id)
          with {:ok, approved} <- transition(repo, csr, "approved", %{
                 reviewed_by: nil,
                 reviewed_at: DateTime.utc_now()
               }) do
            audit("csr_approved", tenant_id, nil, "csr", csr.id, %{
              subject_dn: csr.subject_dn,
              auto_approved: true
            })

            case forward_to_ca(tenant_id, csr.id) do
              {:ok, _} ->
                Logger.info("csr_auto_approved_and_issued csr_id=#{csr.id}")
              {:error, reason} ->
                Logger.error("csr_auto_approve_ca_failed csr_id=#{csr.id} reason=#{inspect(reason)}")
            end
          end
        end)
      end

    _ ->
      # Manual approval or profile not found — do nothing
      :ok
  end
rescue
  _ -> :ok
end
```

- [ ] **Step 4: Run auto-approve tests**

```bash
mix test test/pki_ra_engine/auto_approve_test.exs
```
Expected: All pass

- [ ] **Step 5: Run full test suite**

```bash
mix test --seed 0
```
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add src/pki_ra_engine/lib/pki_ra_engine/csr_validation.ex \
        src/pki_ra_engine/test/pki_ra_engine/auto_approve_test.exs
git commit -m "feat(ra-engine): auto-approve flow for cert profiles with approval_mode=auto"
```

---

## Phase C: Webhook Delivery

### Task 11: Webhook Delivery Module

**Files:**
- Create: `src/pki_ra_engine/lib/pki_ra_engine/webhook_delivery.ex`

- [ ] **Step 1: Implement WebhookDelivery module**

```elixir
defmodule PkiRaEngine.WebhookDelivery do
  @moduledoc """
  Delivers webhook events to API key-configured callback URLs.
  Retries with exponential backoff. HMAC-signed payloads.
  All deliveries are audit-logged.
  """

  require Logger
  alias PkiRaEngine.TenantRepo

  @max_retries 3
  @backoff_ms [1_000, 5_000, 30_000]
  @timeout_ms 10_000

  @doc "Deliver a webhook event for a CSR. Looks up the API key's webhook_url from submitted_by_key_id."
  def deliver_for_csr(tenant_id, csr, event, extra_payload \\ %{}) do
    if csr.submitted_by_key_id do
      repo = TenantRepo.ra_repo(tenant_id)
      case repo.get(PkiRaEngine.Schema.RaApiKey, csr.submitted_by_key_id) do
        %{webhook_url: url, webhook_secret: secret} when is_binary(url) and url != "" ->
          payload = Map.merge(%{
            event: event,
            csr_id: csr.id,
            subject_dn: csr.subject_dn,
            status: csr.status,
            timestamp: DateTime.to_iso8601(DateTime.utc_now())
          }, extra_payload)

          Task.Supervisor.start_child(PkiRaEngine.TaskSupervisor, fn ->
            deliver_with_retry(url, secret, event, payload, tenant_id, 0)
          end)

        _ ->
          :ok  # No webhook configured
      end
    end
  rescue
    _ -> :ok
  end

  @doc "Deliver a webhook for a certificate event (by serial number)."
  def deliver_for_cert(tenant_id, serial_number, event, payload) do
    # Look up the CSR that produced this certificate to find the API key
    repo = TenantRepo.ra_repo(tenant_id)
    import Ecto.Query

    case repo.one(from c in PkiRaEngine.Schema.CsrRequest,
      where: c.issued_cert_serial == ^serial_number and not is_nil(c.submitted_by_key_id),
      limit: 1
    ) do
      %{submitted_by_key_id: key_id} = csr ->
        deliver_for_csr(tenant_id, csr, event, payload)
      _ ->
        :ok
    end
  rescue
    _ -> :ok
  end

  defp deliver_with_retry(url, secret, event, payload, tenant_id, attempt) do
    body = Jason.encode!(payload)
    signature = compute_signature(secret, body)
    timestamp = DateTime.to_iso8601(DateTime.utc_now())

    headers = [
      {"content-type", "application/json"},
      {"x-webhook-signature", signature},
      {"x-webhook-event", to_string(event)},
      {"x-webhook-timestamp", timestamp}
    ]

    case Req.post(url, body: body, headers: headers, receive_timeout: @timeout_ms) do
      {:ok, %{status: status}} when status in 200..299 ->
        Logger.info("webhook_delivered event=#{event} url=#{url} status=#{status} attempt=#{attempt + 1}")
        audit_webhook("webhook_delivered", tenant_id, %{event: event, url: url, status: status, attempt: attempt + 1})

      {:ok, %{status: status}} ->
        Logger.warning("webhook_failed event=#{event} url=#{url} status=#{status} attempt=#{attempt + 1}")
        maybe_retry(url, secret, event, payload, tenant_id, attempt, "HTTP #{status}")

      {:error, reason} ->
        Logger.warning("webhook_failed event=#{event} url=#{url} error=#{inspect(reason)} attempt=#{attempt + 1}")
        maybe_retry(url, secret, event, payload, tenant_id, attempt, inspect(reason))
    end
  rescue
    e ->
      Logger.error("webhook_crash event=#{event} url=#{url} error=#{Exception.message(e)}")
      maybe_retry(url, secret, event, payload, tenant_id, attempt, Exception.message(e))
  end

  defp maybe_retry(url, secret, event, payload, tenant_id, attempt, error) do
    if attempt < @max_retries - 1 do
      delay = Enum.at(@backoff_ms, attempt, 30_000)
      Process.sleep(delay)
      deliver_with_retry(url, secret, event, payload, tenant_id, attempt + 1)
    else
      Logger.error("webhook_exhausted event=#{event} url=#{url} attempts=#{@max_retries}")
      audit_webhook("webhook_failed", tenant_id, %{event: event, url: url, error: error, attempts_exhausted: true})
    end
  end

  defp compute_signature(nil, _body), do: "none"
  defp compute_signature(secret, body) do
    :crypto.mac(:hmac, :sha256, secret, body) |> Base.encode16(case: :lower)
  end

  defp audit_webhook(action, tenant_id, details) do
    PkiPlatformEngine.PlatformAudit.log(action, %{
      tenant_id: tenant_id,
      portal: "ra",
      details: details
    })
  rescue
    _ -> :ok
  end
end
```

- [ ] **Step 2: Wire webhook calls into CsrValidation lifecycle events**

In `csr_validation.ex`, add webhook delivery calls after each lifecycle event:

After `submit_csr` succeeds:
```elixir
PkiRaEngine.WebhookDelivery.deliver_for_csr(tenant_id, csr, "csr_submitted")
```

After `validate_csr` completes:
```elixir
PkiRaEngine.WebhookDelivery.deliver_for_csr(tenant_id, validated, "csr_validated", %{result: validated.status})
```

After `approve_csr`:
```elixir
PkiRaEngine.WebhookDelivery.deliver_for_csr(tenant_id, approved_csr, "csr_approved")
```

After `reject_csr`:
```elixir
PkiRaEngine.WebhookDelivery.deliver_for_csr(tenant_id, rejected_csr, "csr_rejected", %{reason: reason})
```

After `mark_issued`:
```elixir
PkiRaEngine.WebhookDelivery.deliver_for_csr(tenant_id, issued_csr, "cert_issued", %{serial_number: cert_serial})
```

After `revoke_certificate`:
```elixir
PkiRaEngine.WebhookDelivery.deliver_for_cert(tenant_id, serial_number, "cert_revoked", %{reason: reason})
```

- [ ] **Step 3: Compile and run tests**

```bash
mix compile && mix test --seed 0
```

- [ ] **Step 4: Commit**

```bash
git add src/pki_ra_engine/lib/pki_ra_engine/webhook_delivery.ex \
        src/pki_ra_engine/lib/pki_ra_engine/csr_validation.ex
git commit -m "feat(ra-engine): webhook delivery for all CSR/cert lifecycle events"
```

---

## Phase D: Portal UI

### Task 12: API Key Management Portal Redesign

**Files:**
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/live/api_keys_live.ex`
- Modify: `src/pki_ra_portal/lib/pki_ra_portal/ra_engine_client.ex`
- Modify: `src/pki_ra_portal/lib/pki_ra_portal/ra_engine_client/direct.ex`

- [ ] **Step 1: Rewrite the API key creation form**

Replace the single-input form with a multi-section form:

**Section 1: Basic Info**
- Label (text, required, max 100)
- Key Type (radio: Client Key / Service Key) with descriptions
- Assign to User (dropdown: active RA users)
- Expiry Date (date input, required, min tomorrow)

**Section 2: Access Control**
- Allowed Certificate Profiles (checkboxes: active cert profiles, at least one required)
- IP Whitelist (textarea: one CIDR per line, optional, with help text)
- Rate Limit (number: requests/minute, default 60, range 1-10000)

**Section 3: Webhook (collapsible)**
- Webhook URL (text, must be https://, optional)

**On create success:** Show modal with raw API key and webhook secret (one-time display).

- [ ] **Step 2: Update data loading to include RA users and cert profiles**

In `handle_info(:load_data)`, also load:
- `RaEngineClient.list_portal_users(opts)` for user dropdown
- `RaEngineClient.list_cert_profiles(opts)` for profile checkboxes

- [ ] **Step 3: Update table columns**

Show: Label, Type (badge), Owner, Profiles (count), Rate Limit, Expiry (with warning if <30 days), Status, Actions.

- [ ] **Step 4: Compile and verify**

```bash
cd src/pki_ra_portal && mix compile
```

- [ ] **Step 5: Commit**

```bash
git add src/pki_ra_portal/lib/pki_ra_portal_web/live/api_keys_live.ex \
        src/pki_ra_portal/lib/pki_ra_portal/ra_engine_client.ex \
        src/pki_ra_portal/lib/pki_ra_portal/ra_engine_client/direct.ex
git commit -m "feat(ra-portal): API Key Management — full form with types, profiles, IP, webhooks"
```

---

### Task 13: Cert Profile Approval Mode Toggle

**Files:**
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/live/cert_profiles_live.ex`

- [ ] **Step 1: Add approval_mode to create and edit forms**

Add a radio button group in the cert profile form:

```heex
<div>
  <label class="label text-xs font-medium">Approval Mode</label>
  <div class="flex gap-4 mt-1">
    <label class="flex items-center gap-2 cursor-pointer">
      <input type="radio" name="approval_mode" value="manual"
             checked={Map.get(@template_defaults, :approval_mode, "manual") == "manual"}
             class="radio radio-sm radio-primary" />
      <div>
        <span class="text-sm font-medium">Manual Review</span>
        <p class="text-xs text-base-content/50">Officer must approve each CSR</p>
      </div>
    </label>
    <label class="flex items-center gap-2 cursor-pointer">
      <input type="radio" name="approval_mode" value="auto"
             checked={Map.get(@template_defaults, :approval_mode) == "auto"}
             class="radio radio-sm radio-primary" />
      <div>
        <span class="text-sm font-medium">Auto-Approve</span>
        <p class="text-xs text-base-content/50">Automatically issue if all validations pass</p>
      </div>
    </label>
  </div>
</div>
```

- [ ] **Step 2: Add approval_mode to the table and pass through create/update**

Add "Mode" column showing badge: "Manual" (default) or "Auto" (info). Update `create_profile` event handler to include `approval_mode: params["approval_mode"]` in attrs.

- [ ] **Step 3: Compile**

```bash
mix compile
```

- [ ] **Step 4: Commit**

```bash
git add src/pki_ra_portal/lib/pki_ra_portal_web/live/cert_profiles_live.ex
git commit -m "feat(ra-portal): cert profile approval mode toggle (auto/manual)"
```

---

### Task 14: Rename Service Configs to Validation Endpoints

**Files:**
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/live/service_configs_live.ex`
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/components/layouts.ex`

- [ ] **Step 1: Update sidebar label**

In `layouts.ex`, change the CONFIGURATION section:

```elixir
<.sidebar_link href="/service-configs" icon="hero-globe-alt" label="Validation Endpoints" current={@page_title} />
```

Add `is_active?` clause:
```elixir
defp is_active?("Validation Endpoints", page) when page in ["Service Configs", "Service Configuration", "Validation Endpoints"], do: true
```

- [ ] **Step 2: Update page title and simplify form**

In `service_configs_live.ex`:
- Change `page_title` to `"Validation Endpoints"`
- Update heading text
- Simplify the form: remove rate_limit, ip_whitelist, ip_blacklist fields
- Update service type options to normalized values: `"ocsp_responder"`, `"crl_distribution"`, `"tsa"` with display labels
- Add info banner explaining these are certificate extension endpoints

- [ ] **Step 3: Compile**

```bash
mix compile
```

- [ ] **Step 4: Commit**

```bash
git add src/pki_ra_portal/lib/pki_ra_portal_web/live/service_configs_live.ex \
        src/pki_ra_portal/lib/pki_ra_portal_web/components/layouts.ex
git commit -m "feat(ra-portal): rename Service Configs to Validation Endpoints, simplify form"
```

---

### Task 15: Apply Migrations to Tenant Databases

**Files:** None (operational task)

- [ ] **Step 1: Apply all new migrations to dev and test databases**

```bash
cd src/pki_ra_engine
POSTGRES_PORT=5434 mix ecto.migrate
MIX_ENV=test mix ecto.migrate
```

- [ ] **Step 2: Apply to tenant databases**

Use standalone Elixir script to add new columns to all tenant `ra` schemas (same pattern as previous tenant migration scripts).

- [ ] **Step 3: Run full test suite**

```bash
mix test --seed 0
```
Expected: All pass

- [ ] **Step 4: Compile portal**

```bash
cd src/pki_ra_portal && mix compile
```

- [ ] **Step 5: Final commit**

```bash
git add -A
git commit -m "feat(ra): API Key Management & Service Config redesign — complete"
```

---

## Summary

| Phase | Tasks | Description |
|-------|-------|-------------|
| A | 1-5 | Schema migrations: API key fields, approval_mode, submitted_by_key_id, service config simplification, audit actions |
| B | 6-10 | Engine enforcement: per-key rate limiting, IP whitelist, key type scope, profile restriction, auto-approve flow |
| C | 11 | Webhook delivery with retry, HMAC signing, audit logging |
| D | 12-15 | Portal UI: API key form redesign, approval mode toggle, validation endpoints rename, tenant migrations |
