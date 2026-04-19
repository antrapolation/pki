# Phase D: BYOK-HSM — Bring Your Own Hardware Security Module

**Date:** 2026-04-19
**Goal:** Enable customers to use their own HSM (YubiKey, Entrust Blade, Thales Luna, SafeNet, or any PKCS#11 device) for signing operations, either co-located with the server or on the customer's site via a gateway agent.
**Duration:** ~3 weeks.
**Prerequisite:** Phase A + B + C complete on `feat/phase-a-per-tenant-beam` branch.

---

## 1. Architecture Overview

Three signing backends, selectable per issuer key:

**Software (current)** — key material in `KeyActivation` GenServer memory. Threshold ceremony reconstruction. Default for all existing keys.

**Local HSM** — PKCS#11 device co-located with the BEAM server. Elixir communicates via an Erlang Port (separate OS process) that loads the customer's PKCS#11 `.so` library. SoftHSM2, Entrust, Thales Luna on-site.

**Remote HSM** — PKCS#11 device on the customer's site. A Go agent binary runs next to the HSM, connects to the BEAM backend via gRPC with mTLS (TLS 1.3 minimum). Bidirectional streaming: backend pushes signing requests, agent pushes signatures.

```
Customer Site                         Your Server
┌──────────────────┐                  ┌──────────────────────────┐
│ YubiKey/Entrust/ │                  │ Tenant BEAM node         │
│ Thales/SafeNet   │                  │                          │
│       │          │                  │ KeyStore.Dispatcher      │
│ HSM Agent (Go)   │──gRPC mTLS────►│ ├─ SoftwareAdapter       │
│ (static binary)  │  TLS 1.3        │ ├─ LocalHsmAdapter       │
└──────────────────┘                  │ │  └─ Pkcs11Port (C)     │
                                      │ └─ RemoteHsmAdapter      │
Co-located HSM                        │    └─ HsmGateway (gRPC)  │
┌──────────────────┐                  │                          │
│ SoftHSM2/Entrust │◄─Erlang Port──│                          │
└──────────────────┘                  └──────────────────────────┘
```

### Supported HSMs (via PKCS#11)

| HSM | Library | Deployment |
|-----|---------|------------|
| SoftHSM2 | `libsofthsm2.so` | Local |
| Entrust nShield/Blade | `libcknfast.so` | Local or Remote |
| Thales Luna | `libCryptoki2_64.so` | Local or Remote |
| SafeNet (Gemalto) | `libCryptoki2_64.so` | Local or Remote |
| YubiKey 5 | `libykcs11.so` | Remote (via agent) |
| YubiHSM2 | `yubihsm_pkcs11.so` | Remote (via agent) |
| AWS CloudHSM | `libcloudhsm_pkcs11.so` | Local (on AWS) |

The agent doesn't care what HSM it talks to — it loads whatever `.so` the customer configures.

---

## 2. KeyStore Behaviour

```elixir
defmodule PkiCaEngine.KeyStore do
  @callback sign(issuer_key_id :: binary(), tbs_data :: binary()) ::
    {:ok, signature :: binary()} | {:error, term()}

  @callback get_public_key(issuer_key_id :: binary()) ::
    {:ok, public_key :: binary()} | {:error, term()}

  @callback key_available?(issuer_key_id :: binary()) :: boolean()
end
```

### Dispatcher

`PkiCaEngine.KeyStore.Dispatcher` reads `IssuerKey.keystore_type` and routes to the correct adapter:

- `:software` → `SoftwareAdapter` (wraps `KeyActivation.get_active_key`)
- `:local_hsm` → `LocalHsmAdapter` (Erlang Port to PKCS#11)
- `:remote_hsm` → `RemoteHsmAdapter` (gRPC to agent)

All callers (`CertificateSigning`, `OcspResponder`, `CrlPublisher`) change from:
```elixir
{:ok, private_key} = KeyActivation.get_active_key(issuer_key_id)
{:ok, sig} = PkiCrypto.Algorithm.sign(algo, private_key, tbs)
```
To:
```elixir
{:ok, sig} = PkiCaEngine.KeyStore.Dispatcher.sign(issuer_key_id, tbs)
```

The algorithm is resolved internally from the `IssuerKey` record.

---

## 3. Software Adapter

Wraps the existing `KeyActivation` GenServer. No behavior change for software keystores.

```elixir
defmodule PkiCaEngine.KeyStore.SoftwareAdapter do
  @behaviour PkiCaEngine.KeyStore

  def sign(issuer_key_id, tbs_data) do
    with {:ok, key} <- get_issuer_key(issuer_key_id),
         {:ok, private_key} <- PkiCaEngine.KeyActivation.get_active_key(issuer_key_id),
         algo <- PkiCrypto.Registry.get(key.algorithm) do
      PkiCrypto.Algorithm.sign(algo, private_key, tbs_data)
    end
  end

  def key_available?(issuer_key_id) do
    PkiCaEngine.KeyActivation.is_active?(issuer_key_id)
  end
end
```

Ceremony + threshold activation flow unchanged. Software adapter is the default.

---

## 4. Local HSM Adapter (Erlang Port)

### Port binary (`priv/pkcs11_port`)

Small C program (~200 lines):
- Reads length-prefixed commands from stdin
- Loads PKCS#11 `.so` via `dlopen`
- Calls `C_Initialize`, `C_OpenSession`, `C_Login` on startup
- Handles commands: `sign`, `generate_keypair`, `get_public_key`, `ping`
- Writes length-prefixed responses to stdout
- Crash doesn't affect BEAM

### Pkcs11Port GenServer

One GenServer per HSM slot. Manages the Port lifecycle:
- Spawns C port on init with config (`.so` path, slot ID, PIN)
- Serializes commands via `term_to_binary` / `binary_to_term`
- Handles port crash → restart with backoff
- Shared across issuer keys on the same HSM slot

### Adapter

```elixir
defmodule PkiCaEngine.KeyStore.LocalHsmAdapter do
  @behaviour PkiCaEngine.KeyStore

  def sign(issuer_key_id, tbs_data) do
    with {:ok, key} <- get_issuer_key(issuer_key_id),
         {:ok, port_pid} <- get_or_start_port(key) do
      PkiCaEngine.KeyStore.Pkcs11Port.call(port_pid, {:sign, key.hsm_config["key_label"], tbs_data})
    end
  end

  def key_available?(issuer_key_id) do
    case get_issuer_key(issuer_key_id) do
      {:ok, %{keystore_type: :local_hsm}} -> true
      _ -> false
    end
  end
end
```

### IssuerKey HSM fields

```elixir
%IssuerKey{
  keystore_type: :local_hsm,
  hsm_config: %{
    "library_path" => "/usr/lib/softhsm/libsofthsm2.so",
    "slot_id" => 0,
    "pin" => "encrypted-pin-ref",
    "key_label" => "root-ca-key"
  },
  hsm_key_handle: nil  # populated after first use (PKCS#11 CKA_ID)
}
```

---

## 5. Remote HSM Adapter + gRPC Server

### Protocol (`priv/proto/hsm_gateway.proto`)

```protobuf
syntax = "proto3";
package pki.hsm;

service HsmGateway {
  rpc Connect(stream AgentMessage) returns (stream ServerMessage);
}

message AgentMessage {
  oneof payload {
    RegisterRequest register = 1;
    SignResponse sign_response = 2;
    Heartbeat heartbeat = 3;
  }
}

message ServerMessage {
  oneof payload {
    RegisterResponse register_response = 1;
    SignRequest sign_request = 2;
    HeartbeatAck heartbeat_ack = 3;
  }
}

message RegisterRequest {
  string tenant_id = 1;
  string agent_id = 2;
  repeated string available_key_labels = 3;
}

message RegisterResponse {
  bool accepted = 1;
  string error = 2;
}

message SignRequest {
  string request_id = 1;
  string key_label = 2;
  bytes tbs_data = 3;
  string algorithm = 4;
}

message SignResponse {
  string request_id = 1;
  bytes signature = 2;
  string error = 3;
}

message Heartbeat {
  int64 timestamp = 1;
}

message HeartbeatAck {
  int64 timestamp = 1;
}
```

### HsmGateway GenServer (BEAM side)

- Listens on a per-tenant gRPC port (range 9001-9999, from PortAllocator)
- mTLS: requires client cert signed by the tenant's CA
- TLS 1.3 minimum enforced
- On `Connect` stream: agent registers with key labels, enters bidirectional loop
- `sign_request/3` — sends `SignRequest` to agent stream, waits for `SignResponse` (5s timeout)
- If no agent connected: `{:error, :agent_not_connected}`
- Heartbeat timeout: 30s — if no heartbeat, mark agent disconnected

State:
```elixir
%{
  agent_stream: pid | nil,
  agent_id: String.t() | nil,
  available_keys: [String.t()],
  pending_requests: %{request_id => {from_pid, timer_ref}},
  port: integer
}
```

### Remote Adapter

```elixir
defmodule PkiCaEngine.KeyStore.RemoteHsmAdapter do
  @behaviour PkiCaEngine.KeyStore

  def sign(issuer_key_id, tbs_data) do
    with {:ok, key} <- get_issuer_key(issuer_key_id) do
      PkiCaEngine.HsmGateway.sign_request(
        key.hsm_config["key_label"],
        tbs_data,
        key.algorithm,
        timeout: 5_000
      )
    end
  end

  def key_available?(issuer_key_id) do
    case get_issuer_key(issuer_key_id) do
      {:ok, key} ->
        PkiCaEngine.HsmGateway.agent_connected?() and
          key.hsm_config["key_label"] in PkiCaEngine.HsmGateway.available_keys()
      _ -> false
    end
  end
end
```

---

## 6. Go HSM Agent

Minimal static binary (~500 lines Go).

### Structure

```
hsm-agent/
├── main.go            # CLI entry, config, PKCS#11 init
├── pkcs11.go          # PKCS#11 wrapper (sign, list keys)
├── grpc_client.go     # gRPC bidirectional stream
├── proto/
│   └── hsm_gateway.pb.go
├── config.yaml        # example
├── go.mod
└── Makefile           # cross-compile
```

### Config

```yaml
pkcs11:
  library: "/usr/lib/libykcs11.so"
  slot: 0
  pin: "${HSM_PIN}"

backend:
  url: "grpcs://comp-5.hsm.straptrust.com:9010"
  tls:
    min_version: "1.3"
    client_cert: "/etc/pki/agent-cert.pem"
    client_key: "/etc/pki/agent-key.pem"
    ca_cert: "/etc/pki/ca-chain.pem"

agent:
  id: "agent-01"
  tenant_id: "019d8ffb-f676-7fd4-8456-6dd42683ed9d"
  heartbeat_interval: "10s"
```

### Agent flow

1. Load config, load PKCS#11 `.so`, login to slot
2. List available key labels via `C_FindObjects`
3. Connect to backend gRPC with mTLS (TLS 1.3)
4. Send `RegisterRequest` with tenant_id + available key labels
5. Bidirectional stream loop:
   - Receive `SignRequest` → `C_Sign` on HSM → send `SignResponse`
   - Send `Heartbeat` every 10s
   - On disconnect: reconnect with exponential backoff (1s, 2s, 4s, ... max 60s)

### Build

```makefile
build-linux:
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o bin/hsm-agent-linux-amd64
build-mac:
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -o bin/hsm-agent-darwin-arm64
```

`CGO_ENABLED=1` required for PKCS#11 `dlopen`. Build on target platform or with cross-compilation toolchain.

### Delivery

Customer downloads binary + example config. Configures `.so` path, HSM credentials, backend URL, client certificate. Runs:
```bash
./hsm-agent --config /etc/pki/hsm-agent.yaml
```

---

## 7. IssuerKey Data Model Changes

Add to `PkiMnesia.Structs.IssuerKey`:

```elixir
keystore_type: :software | :local_hsm | :remote_hsm  # default :software
hsm_config: map()           # adapter-specific config
hsm_key_handle: binary()    # PKCS#11 CKA_ID, populated on first use
```

`keystore_type` defaults to `:software`. All existing keys unchanged.

### HSM config per adapter

**Local HSM:**
```elixir
%{
  "library_path" => "/usr/lib/softhsm/libsofthsm2.so",
  "slot_id" => 0,
  "pin" => "encrypted-pin-ref",
  "key_label" => "root-ca-key"
}
```

**Remote HSM:**
```elixir
%{
  "key_label" => "root-ca-key"
}
```
(Agent config lives on the customer's side, not in Mnesia.)

---

## 8. Changes to Existing Code

### Callers updated (3 files)

| File | Change |
|------|--------|
| `pki_ca_engine/certificate_signing.ex` | `KeyActivation.get_active_key` + `Algorithm.sign` → `KeyStore.Dispatcher.sign` |
| `pki_validation/ocsp_responder.ex` | Same pattern |
| `pki_validation/crl_publisher.ex` | Same pattern |

### Tenant supervision tree

`HsmGateway` gRPC server added conditionally — only starts if `HSM_GRPC_PORT` env var is set. Software-only tenants have zero overhead.

### No changes to

- `PkiCrypto` — signing algorithms unchanged
- `PkiMnesia.Repo` — unchanged
- `PkiTenantWeb` — no UI (wizard deferred)
- `PkiReplica` — unchanged
- `KeyActivation` — still used by SoftwareAdapter, unchanged

---

## 9. Security

### mTLS for gRPC

- Agent presents a client certificate issued by the tenant's own CA — dogfooding the PKI product
- Backend validates the cert chain against the tenant's root CA certificate
- TLS 1.3 minimum enforced on both sides
- Agent cert can be revoked via the tenant's CRL

### HSM PIN handling

- Local HSM: PIN stored encrypted in `IssuerKey.hsm_config`, decrypted at runtime by the Pkcs11Port
- Remote HSM: PIN lives on the customer's machine in the agent config (never touches the backend)

### Key material never leaves the HSM

- Local HSM: private key stays in the PKCS#11 device. `C_Sign` is called, signature comes out. Key never exported.
- Remote HSM: signing happens on the customer's machine. Only the TBS data and signature cross the network (both non-sensitive).
- Software keys: private key is in BEAM process memory (unchanged from Phase A). HSM migration is the upgrade path.

---

## 10. Testing Strategy

**KeyStore behaviour tests:**
- Dispatcher routes to correct adapter based on `keystore_type`
- SoftwareAdapter wraps KeyActivation correctly
- Unknown keystore_type returns `{:error, :unknown_keystore_type}`

**LocalHsmAdapter tests:**
- Pkcs11Port lifecycle (start, sign, crash restart)
- Use SoftHSM2 as the test PKCS#11 library
- Sign + verify round-trip via SoftHSM2

**RemoteHsmAdapter tests:**
- HsmGateway accepts agent connection
- Sign request → response round-trip (mock agent in test)
- Agent disconnect → `{:error, :agent_not_connected}`
- Request timeout → `{:error, :timeout}`

**Go agent tests:**
- PKCS#11 key listing with SoftHSM2
- Sign operation with SoftHSM2
- gRPC connect + register + sign flow (integration test against BEAM)
- Reconnection after disconnect

**Integration test:**
- Full flow: create issuer key with `keystore_type: :local_hsm` → sign cert via SoftHSM2
- Full flow: create issuer key with `keystore_type: :remote_hsm` → start Go agent → sign cert via gRPC

---

## 11. Success Criteria

- [ ] `KeyStore.Dispatcher.sign/2` works for all three adapter types
- [ ] Existing software keys continue working unchanged (SoftwareAdapter)
- [ ] SoftHSM2 signing works via Erlang Port (LocalHsmAdapter)
- [ ] Go agent connects to BEAM via gRPC mTLS with TLS 1.3
- [ ] Bidirectional streaming: sign request → HSM → signature response
- [ ] Agent reconnects automatically after disconnect
- [ ] OCSP responder signs via KeyStore (not KeyActivation directly)
- [ ] CRL publisher signs via KeyStore
- [ ] CertificateSigning signs via KeyStore
- [ ] IssuerKey `keystore_type` field persisted in Mnesia
- [ ] gRPC server only starts when configured (zero overhead for software-only tenants)
- [ ] Private key never leaves the HSM boundary

## 12. Out of Scope

- Connect HSM wizard UI — deferred, configure via IEx/config for now
- Key generation on HSM (use HSM vendor tools, import public key to PKI)
- HSM key migration (software → HSM or HSM → HSM)
- Multi-HSM per tenant (one HSM config per issuer key is sufficient)
- Windows agent build (Linux + Mac first)
