# Credential Manager — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement a cryptographic credential system where every user has dual keypairs (signing + KEM), replacing password-only authentication with password + keypair-based cryptographic identity.

**Architecture:** `PkiCaEngine.CredentialManager` module handles credential lifecycle — creation, authentication, key decryption, signing, and attestation. User creation generates signing + KEM keypairs encrypted with a password-derived key (PBKDF2). Login verifies password hash AND decrypts signing key to prove key ownership. Session holds a derived key for on-demand crypto operations.

**Tech Stack:** Elixir, PkiCrypto (Algorithm protocol, Symmetric, Kdf), Ecto, Argon2

**Spec:** `docs/superpowers/specs/2026-03-26-beta2-multi-tenancy-crypto-credentials.md` Sections 3, 7.2

**Depends on:** Plan 1 (pki_crypto) — completed, Plan 2 (pki_tenancy) — completed

---

## File Structure

```
src/pki_ca_engine/lib/pki_ca_engine/
├── credential_manager.ex              — public API
├── credential_manager/
│   ├── credential.ex                  — Ecto schema for credentials table
│   ├── key_ops.ex                     — keypair generation, encryption, decryption
│   └── attestation.ex                 — public key signing/attestation
└── schema/
    └── ca_user.ex                     — updated with credential association

src/pki_ca_engine/priv/repo/migrations/
└── 20260327000002_create_credentials.exs

src/pki_ca_engine/test/pki_ca_engine/
├── credential_manager_test.exs
└── credential_manager/
    ├── key_ops_test.exs
    └── attestation_test.exs
```

---

### Task 1: Create Credential schema + migration

**Files:**
- Create: `src/pki_ca_engine/lib/pki_ca_engine/credential_manager/credential.ex`
- Create: `src/pki_ca_engine/priv/repo/migrations/20260327000002_create_credentials.exs`
- Test: `src/pki_ca_engine/test/pki_ca_engine/credential_manager/credential_test.exs`

Credential schema:
```elixir
schema "credentials" do
  field :credential_type, :string        # "signing" | "kem"
  field :algorithm, :string              # "ECC-P256" | "ECDH-P256" etc
  field :public_key, :binary             # stored plain
  field :encrypted_private_key, :binary  # encrypted with password-derived key
  field :salt, :binary                   # PBKDF2 salt for key derivation
  field :certificate, :binary            # public key signed by creating admin (nullable)
  field :status, :string                 # "active" | "revoked"

  belongs_to :user, PkiCaEngine.Schema.CaUser, type: :binary_id
  timestamps()
end
```

Migration creates `credentials` table in the ca schema with UUIDv7 PK.

- [ ] **Step 1: Write failing tests** — credential creation, validation, associations
- [ ] **Step 2: Create schema**
- [ ] **Step 3: Create migration**
- [ ] **Step 4: Run tests**
- [ ] **Step 5: Commit**

---

### Task 2: Implement KeyOps (keypair generation + encryption)

**Files:**
- Create: `src/pki_ca_engine/lib/pki_ca_engine/credential_manager/key_ops.ex`
- Test: `src/pki_ca_engine/test/pki_ca_engine/credential_manager/key_ops_test.exs`

KeyOps handles:
- `generate_credential_keypair(algorithm, password)` → generates keypair, encrypts private key with PBKDF2-derived key, returns `{public_key, encrypted_private_key, salt}`
- `decrypt_private_key(encrypted_private_key, salt, password)` → derives key from password+salt, decrypts private key
- `verify_key_ownership(encrypted_private_key, salt, password)` → attempts decrypt, returns boolean

```elixir
defmodule PkiCaEngine.CredentialManager.KeyOps do
  alias PkiCrypto.{Algorithm, Kdf, Symmetric, Registry}

  def generate_credential_keypair(algorithm_name, password) do
    algo = Registry.get(algorithm_name)
    {:ok, %{public_key: pub, private_key: priv}} = Algorithm.generate_keypair(algo)

    salt = Kdf.generate_salt()
    {:ok, derived_key} = Kdf.derive_key(password, salt)
    {:ok, encrypted_priv} = Symmetric.encrypt(priv, derived_key)

    {:ok, %{
      public_key: pub,
      encrypted_private_key: encrypted_priv,
      salt: salt
    }}
  end

  def decrypt_private_key(encrypted_private_key, salt, password) do
    {:ok, derived_key} = Kdf.derive_key(password, salt)
    Symmetric.decrypt(encrypted_private_key, derived_key)
  end

  def verify_key_ownership(encrypted_private_key, salt, password) do
    case decrypt_private_key(encrypted_private_key, salt, password) do
      {:ok, _key} -> true
      {:error, _} -> false
    end
  end
end
```

- [ ] **Step 1: Write failing tests** — generate, decrypt round-trip, wrong password fails, verify ownership
- [ ] **Step 2: Implement KeyOps**
- [ ] **Step 3: Run tests**
- [ ] **Step 4: Commit**

---

### Task 3: Implement CredentialManager public API

**Files:**
- Create: `src/pki_ca_engine/lib/pki_ca_engine/credential_manager.ex`
- Test: `src/pki_ca_engine/test/pki_ca_engine/credential_manager_test.exs`

Public API:
```elixir
defmodule PkiCaEngine.CredentialManager do
  # Create a user with dual credentials (signing + KEM)
  def create_user_with_credentials(ca_instance_id, user_attrs, password, opts \\ [])

  # Authenticate: verify password + decrypt signing key
  def authenticate(username, password)

  # Derive session key for storing in encrypted session cookie
  def create_session_key(password, salt)

  # Decrypt a user's signing private key using session key
  def decrypt_signing_key(user_id, session_key)

  # Decrypt a user's KEM private key using session key
  def decrypt_kem_key(user_id, session_key)

  # Sign data using a user's signing key
  def sign(user_id, session_key, data)

  # Decrypt data using a user's KEM key (for key unwrapping)
  def kem_decrypt(user_id, session_key, ciphertext)
end
```

The `create_user_with_credentials` function:
1. Creates the CaUser record
2. Generates signing keypair (algorithm from tenant config or opts)
3. Generates KEM keypair
4. Encrypts both private keys with password-derived key
5. Stores credentials in the credentials table
6. Returns the user with credentials

The `authenticate` function:
1. Looks up user by username
2. Verifies password hash (Argon2)
3. Attempts to decrypt signing private key (proves key ownership)
4. Returns `{:ok, user, session_key}` or `{:error, :invalid_credentials}`

- [ ] **Step 1: Write failing tests**
- [ ] **Step 2: Implement CredentialManager**
- [ ] **Step 3: Run tests**
- [ ] **Step 4: Run full CA Engine test suite**
- [ ] **Step 5: Commit**

---

### Task 4: Update CA User schema for credential association

**Files:**
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/schema/ca_user.ex` — add `has_many :credentials`
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/user_management.ex` — update create_user to use CredentialManager

- [ ] **Step 1: Add association to CaUser schema**
- [ ] **Step 2: Update UserManagement to delegate to CredentialManager for user creation**
- [ ] **Step 3: Run all tests**
- [ ] **Step 4: Commit**

---

### Task 5: Update CA Engine API auth controller

**Files:**
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/api/auth_controller.ex` — use CredentialManager.authenticate
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/api/user_controller.ex` — use CredentialManager.create_user_with_credentials

The auth controller's `login` endpoint now:
1. Calls `CredentialManager.authenticate(username, password)`
2. Returns user data + session_key (encrypted in the response or stored in session)
3. The session_key enables future crypto operations

The user controller's `create` endpoint now:
1. Calls `CredentialManager.create_user_with_credentials(...)`
2. Returns user data (without private keys)

- [ ] **Step 1: Update auth controller**
- [ ] **Step 2: Update user controller**
- [ ] **Step 3: Run all CA Engine tests**
- [ ] **Step 4: Commit**

---

### Task 6: Update CA Portal for credential-aware auth

**Files:**
- Modify: `src/pki_ca_portal/lib/pki_ca_portal_web/controllers/session_controller.ex` — store session_key in session
- Modify: `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client.ex` — add session_key to auth callbacks
- Modify: `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/mock.ex` — mock returns session_key

The portal login flow now:
1. User submits username + password
2. Portal calls engine's auth endpoint
3. Engine returns user + session_key
4. Portal stores session_key in encrypted session cookie
5. Future crypto operations use the session_key

- [ ] **Step 1: Update session controller**
- [ ] **Step 2: Update client behaviour + mock**
- [ ] **Step 3: Run portal tests**
- [ ] **Step 4: Commit and push**

---

## Plan Summary

| Task | What | Tests |
|------|------|-------|
| 1 | Credential schema + migration | ~8 tests |
| 2 | KeyOps (keypair gen + encryption) | ~10 tests |
| 3 | CredentialManager public API | ~12 tests |
| 4 | Update CaUser + UserManagement | Existing pass |
| 5 | Update API controllers | Existing pass |
| 6 | Update CA Portal auth | Portal tests pass |

**Total: ~30 new tests + all existing tests still passing**

Next plan (Plan 4: Keypair ACL + Key Vault) will be written after this plan is implemented.
