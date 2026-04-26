# HSM Wizard UI Design

**Date:** 2026-04-26
**Status:** Approved, pending implementation
**Scope:** Two wizards — CA admin (tenant portal) and platform admin (platform portal)

---

## Overview

The HSM integration today requires manual configuration of the Go agent, keystore records, and mTLS certs. This wizard UI guides each actor through their part of the setup without requiring backend knowledge.

Two distinct flows:

1. **CA Admin Wizard** (tenant portal) — 5-step LiveView wizard to wire the Go agent to the CA engine: configure mTLS, generate an agent token, wait for agent registration, select a key, create the keystore.
2. **Platform Admin Wizard** (platform portal) — 4-step modal to register a physical HSM device and assign it to tenants.

---

## 1. Data Layer

### New Mnesia struct: `PkiMnesia.Structs.HsmAgentSetup`

Persists CA admin wizard draft state across sessions.

```elixir
@fields [
  :id,               # UUID
  :ca_instance_id,
  :tenant_id,
  :agent_id,         # operator-chosen (e.g. "prod-hsm-01")
  :gateway_port,     # integer
  :cert_mode,        # "generated" | "uploaded"
  :server_cert_pem,
  :server_key_pem,   # deleted when wizard completes
  :ca_cert_pem,      # given to agent operator
  :auth_token_hash,  # SHA-256 of plaintext; plaintext shown once only
  :key_labels,       # list — populated when agent connects
  :selected_key_label,
  :expected_agent_id,
  :status,           # "pending_agent" | "agent_connected" | "complete"
  :inserted_at,
  :updated_at
]
```

`server_key_pem` is zeroed out on wizard completion — it lives only as long as setup is in progress.

---

## 2. CA Admin Wizard (Tenant Portal)

### New files

```
src/pki_tenant_web/lib/pki_tenant_web/ca/live/hsm_wizard_live.ex
src/pki_tenant_web/lib/pki_tenant_web/ca/live/hsm_wizard_live.html.heex
src/pki_ca_engine/lib/pki_ca_engine/hsm_agent_setup.ex
```

### Routes (added to `ca_router.ex`)

```elixir
live "/hsm-wizard", HsmWizardLive, :new
live "/hsm-wizard/:setup_id", HsmWizardLive, :resume
```

### LiveView state

```elixir
%{
  step:      :gateway | :token | :waiting | :keys | :keystore | :done,
  setup:     %HsmAgentSetup{},
  cert_mode: :generate | :upload,
  error:     nil | String.t()
}
```

### Layout

Left sidebar showing all 5 steps (matches the existing ceremony wizard pattern), with the active step highlighted. Step content fills the right panel.

### Step behaviour

**`:gateway` — Gateway Port & TLS**
- Port number input
- Cert mode toggle: "Generate for me" / "Use my own certs"
- *Generate path*: calls `HsmAgentSetup.generate_certs/1` → `PkiCrypto.X509Builder.self_sign("ECC-P256", ...)` with 2-year validity. Shows download link for CA cert.
- *Upload path*: file inputs for server cert, server key, CA cert.
- Saves draft on Next.

**`:token` — Agent Token**
- Agent ID input (e.g. "prod-hsm-01")
- "Generate Token" button → `HsmAgentSetup.generate_token/0` (`:crypto.strong_rand_bytes(32) |> Base.url_encode64`). Plaintext shown once in a copy-to-clipboard box.
- Token stored as `SHA-256(plaintext)` in draft.
- Downloads a ready-to-use `agent-config.yaml` snippet via `HsmAgentSetup.build_agent_config_yaml/1`. The YAML embeds the CA cert PEM inline under `backend.tls.ca_cert_pem` so the operator only needs one file.
- Saves draft on Next.

**`:waiting` — Wait for Agent**

*Polling state (tab open):*
- `Process.send_after(self(), :poll_agent, 3_000)` on step entry.
- Each tick: `HsmGateway.agent_connected?/1`.
- On connect: `HsmGateway.available_keys/1` → saves labels to draft → transition to `:keys`.
- Shows agent config summary (gateway URL, agent ID, token masked).
- "Download agent-config.yaml" button.
- "Save progress and come back later" link → sets `status: "pending_agent"`, redirects to HSM Devices page.

*Resume state (admin returns later):*
- `HsmDevicesLive` calls `HsmAgentSetup.pending_for_ca/1` on mount.
- If pending draft found: renders yellow resume banner ("HSM setup in progress — waiting for agent `prod-hsm-01`") with "Resume setup →" button.
- `AgentHandler` broadcasts `{:agent_connected, agent_id, key_labels}` on `"hsm_gateway:#{tenant_id}"` PubSub topic when agent registers.
- `HsmDevicesLive` subscribes to this topic and transitions banner to green ("Agent connected! Continue →") without page reload.

**`:keys` — Key Selection**
- Radio list of `draft.key_labels` advertised by the agent.
- Selecting a key sets `selected_key_label` and `expected_agent_id` (bound to the current agent).

**`:keystore` — Create Keystore**
- Summary of chosen configuration.
- "Create Keystore" button calls `KeystoreManagement.configure_keystore/2` with:
  ```elixir
  %{
    type: "remote_hsm",
    config: %{
      agent_id: draft.agent_id,
      key_label: draft.selected_key_label,
      expected_agent_id: draft.expected_agent_id
    }
  }
  ```
- On success: `HsmAgentSetup.complete/2` wipes `server_key_pem`, sets status `"complete"`. Redirects to Keystores page with success flash.

---

## 3. Platform Admin Wizard (Platform Portal)

### New file

```
src/pki_platform_portal/lib/pki_platform_portal_web/live/hsm_wizard_component.ex
```

A LiveComponent rendered as a modal from `HsmDevicesLive`. No new route — "Register Device" button sets `@live_action: :new_device` on the existing `/hsm-devices` route.

### Modal steps

**`:device_info`** — Label, PKCS#11 library path, slot ID.

**`:probe`** — Calls `HsmManagement.register_device(attrs)` which probes PKCS#11 and creates the `HsmDevice` record. Spinner while probing. Fail-closed: error shown inline with retry. Must succeed to continue.

**`:assign`** — Multi-select tenant checklist. Calls `HsmManagement.grant_tenant_access/2` per selection. Skippable via "Assign later" → jumps to Done.

**`:done`** — Summary card: device label, manufacturer (from probe), slot count. Link to device detail page.

No draft state needed — the `HsmDevice` record is the persistent artifact.

---

## 4. Backend Module: `PkiCaEngine.HsmAgentSetup`

```elixir
create_draft(ca_instance_id, tenant_id) :: {:ok, %HsmAgentSetup{}}
save_gateway(setup_id, port, cert_mode, cert_pem, key_pem, ca_cert_pem) :: {:ok, setup}
generate_certs(ca_instance_id) :: {:ok, %{cert_pem, key_pem, ca_cert_pem}}
save_token(setup_id, agent_id, token_plaintext) :: {:ok, setup}
generate_token() :: binary
pending_for_ca(ca_instance_id) :: {:ok, %HsmAgentSetup{}} | {:error, :not_found}
mark_agent_connected(setup_id, key_labels) :: {:ok, setup}
complete(setup_id, selected_key_label) :: {:ok, setup}  # wipes server_key_pem
build_agent_config_yaml(setup) :: binary
```

### Token authentication in `AgentHandler`

`authenticate_agent/4` currently reads tokens from app config. Wizard-created agents use a second lookup path: match `HsmAgentSetup` records where `agent_id` matches and `SHA-256(presented_token) == auth_token_hash`. Both paths coexist.

### PubSub broadcast in `AgentHandler`

After successful `register_agent`, broadcast:
```elixir
Phoenix.PubSub.broadcast(
  PkiTenantWeb.PubSub,
  "hsm_gateway:#{tenant_id}",
  {:agent_connected, agent_id, key_labels}
)
```

`HsmDevicesLive` subscribes to this topic on mount.

---

## 5. Existing files modified

| File | Change |
|------|--------|
| `pki_mnesia/lib/pki_mnesia/structs/hsm_agent_setup.ex` | New struct |
| `pki_tenant_web/.../ca_router.ex` | Add two wizard routes |
| `pki_tenant_web/.../ca/live/hsm_devices_live.ex` | Resume banner + PubSub subscription |
| `pki_ca_engine/.../hsm_gateway/agent_handler.ex` | PubSub broadcast on register |
| `pki_platform_portal_web/.../live/hsm_devices_live.ex` | Open wizard modal on "Register Device" |

---

## 6. Out of scope

- HSM key generation on the device (use existing keys only)
- Multi-agent (one agent per CA instance for now)
- Cert rotation UI
- Windows HSM agent build
