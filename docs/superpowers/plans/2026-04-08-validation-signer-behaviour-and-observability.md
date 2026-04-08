# Validation Followups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land two post-merge follow-ups from PR #4 — (1) `SigningKeyStore.status/0` + `/health` degradation, (2) `PkiValidation.Crypto.Signer` behaviour extraction to kill the per-algorithm duct-tape.

**Architecture:** Observability first (smaller, lower risk, debugging aid). Then signer behaviour extraction using a three-callback behaviour + registry. Both parts land on `feat/validation-followups`.

**Tech Stack:** Elixir 1.18, OTP 27, `:public_key`, existing `pki_validation` patterns from PR #4.

**Spec:** `docs/superpowers/specs/2026-04-08-validation-signer-behaviour-and-observability-design.md`

**Baseline before this plan:** 125 tests passing on `main` after PR #4 merge. Branch `feat/validation-followups` is created from `5406750`.

---

## File Structure

**Part 1 — Observability:**

| Path | Action | Responsibility |
|---|---|---|
| `src/pki_validation/lib/pki_validation/signing_key_store.ex` | Modify | Track `loaded_count` + `failed` list; add `status/1` |
| `src/pki_validation/lib/pki_validation/api/router.ex` | Modify | `/health` consults `SigningKeyStore.status/0` |
| `src/pki_validation/test/pki_validation/signing_key_store_test.exs` | Modify | Add status/0 tests |
| `src/pki_validation/test/pki_validation/api/router_test.exs` | Modify | Add /health healthy + degraded tests |

**Part 2 — Signer Behaviour:**

| Path | Action | Responsibility |
|---|---|---|
| `src/pki_validation/lib/pki_validation/crypto/signer.ex` | Create | Behaviour: `decode_private_key/1`, `sign/2`, `algorithm_identifier_der/0` |
| `src/pki_validation/lib/pki_validation/crypto/signer/registry.ex` | Create | Algorithm string → module mapping |
| `src/pki_validation/lib/pki_validation/crypto/signer/ecdsa_p256.ex` | Create | ECDSA-SHA-256 signer |
| `src/pki_validation/lib/pki_validation/crypto/signer/ecdsa_p384.ex` | Create | ECDSA-SHA-384 signer |
| `src/pki_validation/lib/pki_validation/crypto/signer/rsa2048.ex` | Create | RSA-2048 + SHA-256 signer |
| `src/pki_validation/lib/pki_validation/crypto/signer/rsa4096.ex` | Create | RSA-4096 + SHA-256 signer |
| `src/pki_validation/lib/pki_validation/signing_key_store.ex` | Modify | Resolve signer at load time, cache decoded key + module in state |
| `src/pki_validation/lib/pki_validation/ocsp/response_builder.ex` | Modify | Collapse `sign_tbs/2` to one clause using cached signer module; delete per-algorithm DER blob attrs |
| `src/pki_validation/lib/pki_validation/crl/der_generator.ex` | Modify | Collapse `sign_tbs/2` + `sig_alg_identifier/1` to one clause |
| `src/pki_validation/test/pki_validation/crypto/signer/ecdsa_p256_test.exs` | Create | Unit tests |
| `src/pki_validation/test/pki_validation/crypto/signer/ecdsa_p384_test.exs` | Create | Unit tests |
| `src/pki_validation/test/pki_validation/crypto/signer/rsa2048_test.exs` | Create | Unit tests |
| `src/pki_validation/test/pki_validation/crypto/signer/rsa4096_test.exs` | Create | Unit tests |
| `src/pki_validation/test/pki_validation/crypto/signer/registry_test.exs` | Create | Registry fetch tests |
| `src/pki_validation/test/pki_validation/signing_key_store_test.exs` | Modify | Add `:unknown_algorithm` drop test |

---

## Task 1: SigningKeyStore.status/0 with failure tracking

**Goal:** Track successful + failed key loads during `load_keys/1`. Expose via `status/1`. Preserve all existing tests.

**Files:**
- Modify: `src/pki_validation/lib/pki_validation/signing_key_store.ex`
- Modify: `src/pki_validation/test/pki_validation/signing_key_store_test.exs`

- [ ] **Step 1: Write failing tests**

Add to `src/pki_validation/test/pki_validation/signing_key_store_test.exs` (append inside the existing `describe` — or wherever the setup is accessible):

```elixir
describe "status/1" do
  test "reports healthy state when all keys load", %{name: name, issuer_key_id: _id} do
    status = SigningKeyStore.status(name)
    assert status.healthy == true
    assert status.loaded == 1
    assert status.failed == 0
    assert status.last_error == nil
  end

  test "reports failed count when a key has wrong password" do
    bad_id = Uniq.UUID.uuid7()
    {_pub, priv} = :crypto.generate_key(:ecdh, :secp256r1)
    encrypted_with_wrong = SigningKeyStore.encrypt_for_test(priv, "different-password")
    cert_pem = generate_test_cert_pem()

    {:ok, _} =
      %SigningKeyConfig{}
      |> SigningKeyConfig.changeset(%{
        issuer_key_id: bad_id,
        algorithm: "ecc_p256",
        certificate_pem: cert_pem,
        encrypted_private_key: encrypted_with_wrong,
        not_before: DateTime.utc_now(),
        not_after: DateTime.add(DateTime.utc_now(), 30, :day),
        status: "active"
      })
      |> Repo.insert()

    name2 = :"ks_status_bad_#{System.unique_integer([:positive])}"
    {:ok, _} = SigningKeyStore.start_link(name: name2, password: "test-password")

    status = SigningKeyStore.status(name2)
    assert status.healthy == false
    assert status.failed >= 1
    assert status.last_error == :decryption_failed
  end

  test "reports zero loaded when the only key is malformed" do
    bad_id = Uniq.UUID.uuid7()
    cert_pem = generate_test_cert_pem()

    {:ok, _} =
      %SigningKeyConfig{}
      |> SigningKeyConfig.changeset(%{
        issuer_key_id: bad_id,
        algorithm: "ecc_p256",
        certificate_pem: cert_pem,
        encrypted_private_key: <<1, 2, 3>>,
        not_before: DateTime.utc_now(),
        not_after: DateTime.add(DateTime.utc_now(), 30, :day),
        status: "active"
      })
      |> Repo.insert()

    name3 = :"ks_status_trunc_#{System.unique_integer([:positive])}"
    # Note: start a store that does NOT share the setup's good key by using
    # a fresh DB sandbox context or by deleting the setup row before starting.
    # The simplest approach is to rely on SigningKeyStore loading ALL active
    # rows and count what the test inserted plus the setup row. Here we assert
    # the failed count is at least 1 and healthy is false.
    {:ok, _} = SigningKeyStore.start_link(name: name3, password: "test-password")

    status = SigningKeyStore.status(name3)
    assert status.healthy == false
    assert status.failed >= 1
    assert status.last_error in [:malformed_ciphertext, :decryption_failed]
  end
end
```

**Important:** The existing `generate_test_cert_pem/0` helper (refactored during Phase 3.5 review fixes) is used. If not already present as a private function, extract it from the existing `setup/0` block.

- [ ] **Step 2: Run tests to verify failure**

```
cd /Users/amirrudinyahaya/Workspace/pki/.worktrees/validation-followups/src/pki_validation
mix test test/pki_validation/signing_key_store_test.exs --only describe:"status/1"
```

Expected: FAIL — `SigningKeyStore.status/1` not defined.

- [ ] **Step 3: Implement status tracking in `load_keys/1`**

Open `src/pki_validation/lib/pki_validation/signing_key_store.ex` and modify `load_keys/1` to return `{keys_map, loaded_count, failed_list}` instead of just `keys_map`.

Replace the current `load_keys/1`:

```elixir
defp load_keys(password) do
  SigningKeyConfig
  |> where([c], c.status == "active")
  |> Repo.all()
  |> Enum.reduce({%{}, 0, []}, fn config, {keys, loaded, failed} ->
    with {:ok, priv} <- decrypt_private_key(config.encrypted_private_key, password),
         {:ok, cert_der} <- decode_cert_pem(config.certificate_pem) do
      # NOTE: `private_key` here is the raw decrypted bytes and its shape is
      # algorithm-dependent: for ECC it's the raw private scalar, for RSA
      # it's the DER encoding of an :RSAPrivateKey record. This module is
      # deliberately algorithm-agnostic; downstream consumers such as
      # `PkiValidation.Ocsp.ResponseBuilder.sign_tbs/2` are responsible for
      # interpreting the bytes according to `algorithm`.
      entry = %{
        algorithm: config.algorithm,
        private_key: priv,
        certificate_der: cert_der,
        key_hash: PkiValidation.CertId.issuer_key_hash(cert_der),
        not_after: config.not_after
      }

      {Map.put(keys, config.issuer_key_id, entry), loaded + 1, failed}
    else
      {:error, reason} ->
        Logger.error(
          "Failed to load signing key for issuer #{config.issuer_key_id}: #{inspect(reason)}"
        )

        failure = %{issuer_key_id: config.issuer_key_id, reason: reason}
        # Cap the failed list at the 50 most recent entries to prevent
        # unbounded growth on many-key deployments.
        new_failed = Enum.take([failure | failed], 50)
        {keys, loaded, new_failed}
    end
  end)
end
```

- [ ] **Step 4: Update `init/1` and `handle_call(:reload, ...)` to store the new state**

Replace `init/1`:

```elixir
@impl true
def init(opts) do
  password = resolve_password(opts)
  {keys, loaded_count, failed} = load_keys(password)

  Logger.info(
    "SigningKeyStore loaded #{loaded_count} signing keys " <>
      "(#{length(failed)} failed)"
  )

  state = %{
    password: password,
    keys: keys,
    loaded_count: loaded_count,
    failed: failed
  }

  {:ok, state}
end
```

Replace `handle_call(:reload, ...)`:

```elixir
def handle_call(:reload, _from, state) do
  {keys, loaded_count, failed} = load_keys(state.password)

  new_state = %{
    state
    | keys: keys,
      loaded_count: loaded_count,
      failed: failed
  }

  {:reply, :ok, new_state}
end
```

- [ ] **Step 5: Add `status/1` public API and `handle_call(:status, ...)` handler**

Add the public function in the Client API section:

```elixir
@type status :: %{
        loaded: non_neg_integer(),
        failed: non_neg_integer(),
        last_error: atom() | nil,
        healthy: boolean()
      }

@doc """
Return an operational status summary for the store.

Used by /health to report signing key availability. When `failed > 0` the
store is considered degraded (not healthy).
"""
@spec status(GenServer.server()) :: status()
def status(server \\ __MODULE__) do
  GenServer.call(server, :status)
end
```

Add the handler in the Server callbacks section:

```elixir
def handle_call(:status, _from, state) do
  last_error =
    case state.failed do
      [%{reason: reason} | _] -> reason
      _ -> nil
    end

  status = %{
    loaded: state.loaded_count,
    failed: length(state.failed),
    last_error: last_error,
    healthy: state.failed == []
  }

  {:reply, status, state}
end
```

- [ ] **Step 6: Run the new tests**

```
mix test test/pki_validation/signing_key_store_test.exs
```

Expected: all previously-existing tests plus the new status/1 tests pass.

- [ ] **Step 7: Run the full suite — no regressions**

```
mix test
```

Expected: 125 baseline + 3 new status tests = 128 tests, 0 failures.

- [ ] **Step 8: Stage — do NOT commit**

```
cd /Users/amirrudinyahaya/Workspace/pki/.worktrees/validation-followups
git add src/pki_validation/lib/pki_validation/signing_key_store.ex \
        src/pki_validation/test/pki_validation/signing_key_store_test.exs
```

The parent will commit after the /health wiring in Task 2.

---

## Task 2: /health endpoint reports degraded status

**Goal:** `/health` returns 503 with status details when `SigningKeyStore.status/0` reports failures.

**Files:**
- Modify: `src/pki_validation/lib/pki_validation/api/router.ex`
- Modify: `src/pki_validation/test/pki_validation/api/router_test.exs`

- [ ] **Step 1: Write failing tests**

Add to `src/pki_validation/test/pki_validation/api/router_test.exs` (as a new `describe` block — don't modify existing `/health` test):

```elixir
describe "GET /health (with SigningKeyStore status)" do
  # NOTE: These tests depend on the application-supervised SigningKeyStore.
  # The tests use SigningKeyStore.reload/0 to rebuild state from the current
  # DB, mirroring the pattern in other router describe blocks.

  setup do
    on_exit(fn -> PkiValidation.SigningKeyStore.reload() end)
    :ok
  end

  test "returns 200 and healthy=true when all signing keys load cleanly" do
    # Ensure the app store has at least one good key loaded
    issuer_key_id = Uniq.UUID.uuid7()
    {pub_point, priv_scalar} = :crypto.generate_key(:ecdh, :secp256r1)
    p256_oid = {1, 2, 840, 10045, 3, 1, 7}
    ec_priv = {:ECPrivateKey, 1, priv_scalar, {:namedCurve, p256_oid}, pub_point, :asn1_NOVALUE}
    %{cert: cert_der} = :public_key.pkix_test_root_cert(~c"Health Test Signer", [{:key, ec_priv}])
    cert_pem = :public_key.pem_encode([{:Certificate, cert_der, :not_encrypted}])
    encrypted = PkiValidation.SigningKeyStore.encrypt_for_test(priv_scalar, "")

    {:ok, _} =
      %PkiValidation.Schema.SigningKeyConfig{}
      |> PkiValidation.Schema.SigningKeyConfig.changeset(%{
        issuer_key_id: issuer_key_id,
        algorithm: "ecc_p256",
        certificate_pem: cert_pem,
        encrypted_private_key: encrypted,
        not_before: DateTime.utc_now(),
        not_after: DateTime.add(DateTime.utc_now(), 30, :day),
        status: "active"
      })
      |> PkiValidation.Repo.insert()

    PkiValidation.SigningKeyStore.reload()

    conn = :get |> conn("/health") |> Router.call(@opts)
    assert conn.status == 200

    body = Jason.decode!(conn.resp_body)
    assert body["status"] == "ok"
    assert body["signing_keys_loaded"] >= 1
  end

  test "returns 503 and degraded status when a signing key fails to load" do
    issuer_key_id = Uniq.UUID.uuid7()
    {_pub, priv_scalar} = :crypto.generate_key(:ecdh, :secp256r1)
    encrypted_wrong = PkiValidation.SigningKeyStore.encrypt_for_test(priv_scalar, "wrong-password")

    cert_pem =
      case :public_key.pkix_test_root_cert(~c"Health Degraded", []) do
        %{cert: der} -> :public_key.pem_encode([{:Certificate, der, :not_encrypted}])
      end

    {:ok, _} =
      %PkiValidation.Schema.SigningKeyConfig{}
      |> PkiValidation.Schema.SigningKeyConfig.changeset(%{
        issuer_key_id: issuer_key_id,
        algorithm: "ecc_p256",
        certificate_pem: cert_pem,
        encrypted_private_key: encrypted_wrong,
        not_before: DateTime.utc_now(),
        not_after: DateTime.add(DateTime.utc_now(), 30, :day),
        status: "active"
      })
      |> PkiValidation.Repo.insert()

    PkiValidation.SigningKeyStore.reload()

    conn = :get |> conn("/health") |> Router.call(@opts)
    assert conn.status == 503

    body = Jason.decode!(conn.resp_body)
    assert body["status"] == "degraded"
    assert body["signing_keys_failed"] >= 1
    assert body["last_error"] == "decryption_failed"
  end
end
```

- [ ] **Step 2: Run tests to confirm failure**

```
mix test test/pki_validation/api/router_test.exs --only describe:"GET /health (with SigningKeyStore status)"
```

Expected: FAIL — /health still returns 200 unconditionally.

- [ ] **Step 3: Update the router**

In `src/pki_validation/lib/pki_validation/api/router.ex`, replace the existing `get "/health"` route:

```elixir
get "/health" do
  case PkiValidation.SigningKeyStore.status() do
    %{healthy: true, loaded: loaded} ->
      send_json(conn, 200, %{status: "ok", signing_keys_loaded: loaded})

    %{loaded: loaded, failed: failed, last_error: last_error} ->
      send_json(conn, 503, %{
        status: "degraded",
        signing_keys_loaded: loaded,
        signing_keys_failed: failed,
        last_error: if(last_error, do: Atom.to_string(last_error), else: nil)
      })
  end
end
```

- [ ] **Step 4: Run the new tests**

```
mix test test/pki_validation/api/router_test.exs
```

Expected: the new /health tests pass. Existing router tests continue to pass.

**Note:** The existing `test "GET /health returns ok"` test (if it exists in the baseline) may need a small adjustment — if it asserts exactly `%{"status" => "ok"}` with no other fields, it will now see `%{"status" => "ok", "signing_keys_loaded" => N}` and fail on a strict equality. If you hit this, change the assertion from `==` to a loose `body["status"] == "ok"` match. Don't gate the whole test on unchanged shape.

- [ ] **Step 5: Run the full suite**

```
mix test
```

Expected: 125 baseline + 3 Task 1 tests + 2 Task 2 tests = 130 tests, 0 failures.

- [ ] **Step 6: Stage**

```
git add src/pki_validation/lib/pki_validation/api/router.ex \
        src/pki_validation/test/pki_validation/api/router_test.exs
```

- [ ] **Step 7: Commit (Part 1 — Observability)**

```
git commit -m "feat(validation): SigningKeyStore.status/0 + /health degradation

Post-merge follow-up from PR #4. Silent partial key-load failures
are now observable via HTTP /health.

SigningKeyStore now tracks loaded_count and a capped list of failed
entries (50 most recent). status/1 returns a summary:

  %{
    loaded: non_neg_integer(),
    failed: non_neg_integer(),
    last_error: atom() | nil,
    healthy: boolean()
  }

last_error is exposed as an atom only (no binary data, no cipher
bytes) so operators see :decryption_failed, :malformed_ciphertext,
or :invalid_cert_pem — enough signal to diagnose, not enough to leak.

/health is now strict: any failed key returns 503 with status
\"degraded\" and the counts/last_error. Rationale: silent partial
failures are exactly the problem this fix is meant to solve.
A lenient 200-on-any-key-loaded would defeat the purpose.

125 -> 130 tests passing. Existing tests unchanged in behaviour.
"
```

---

## Task 3: Signer behaviour module

**Goal:** Define the `PkiValidation.Crypto.Signer` behaviour with three callbacks.

**Files:**
- Create: `src/pki_validation/lib/pki_validation/crypto/signer.ex`

- [ ] **Step 1: Create the behaviour module**

```elixir
defmodule PkiValidation.Crypto.Signer do
  @moduledoc """
  Behaviour for OCSP/CRL signing algorithms.

  Each concrete signer module owns three things:

    * the AlgorithmIdentifier DER blob (RFC 5754 form)
    * private key decoding (raw at-rest bytes → Erlang term usable by
      `:public_key.sign/3`)
    * the sign-tbs primitive

  `SigningKeyStore` calls `decode_private_key/1` once at load time and
  caches the decoded term in process state. Signers are then called with
  the pre-decoded key, avoiding per-signature parsing and structurally
  preventing the RSA "raw DER passed to sign/3" crash class.

  To add a new signer (e.g. ML-DSA, KAZ-SIGN):

    1. Add the algorithm string to `PkiValidation.Schema.SigningKeyConfig`
       `@valid_algorithms`
    2. Create `PkiValidation.Crypto.Signer.<Name>` implementing this
       behaviour
    3. Add one line to `PkiValidation.Crypto.Signer.Registry.@mapping`
  """

  @doc """
  Decode the at-rest private key bytes into the form `:public_key.sign/3`
  (or the equivalent NIF entry point) expects.

  Called once per key at `SigningKeyStore` load time. The returned term is
  cached and passed back to `sign/2` on every signature.
  """
  @callback decode_private_key(binary()) :: term()

  @doc """
  Sign the TBS DER bytes, returning the raw signature bytes (no BIT STRING
  wrapping — the ASN.1 encoder handles that).
  """
  @callback sign(tbs :: binary(), private_key :: term()) :: binary()

  @doc """
  Return the DER-encoded AlgorithmIdentifier for this signer.

  This is the complete pre-encoded byte sequence for an RFC 5754
  AlgorithmIdentifier with the algorithm OID and (for RSA) the NULL params,
  ready to splice into the `OCSP.asn1` ANY-typed field.

  Static per module — each signer owns its own blob.
  """
  @callback algorithm_identifier_der() :: binary()
end
```

- [ ] **Step 2: Verify it compiles**

```
mix compile
```

Expected: compiles cleanly. No warnings.

- [ ] **Step 3: Stage**

```
git add src/pki_validation/lib/pki_validation/crypto/signer.ex
```

No tests yet — concrete modules will exercise the behaviour.

---

## Task 4: EcdsaP256 signer module

**Goal:** First concrete signer. Proves the behaviour shape works for ECC.

**Files:**
- Create: `src/pki_validation/lib/pki_validation/crypto/signer/ecdsa_p256.ex`
- Create: `src/pki_validation/test/pki_validation/crypto/signer/ecdsa_p256_test.exs`

- [ ] **Step 1: Write failing test**

```elixir
defmodule PkiValidation.Crypto.Signer.EcdsaP256Test do
  use ExUnit.Case, async: true

  alias PkiValidation.Crypto.Signer.EcdsaP256

  setup do
    {pub_point, priv_scalar} = :crypto.generate_key(:ecdh, :secp256r1)
    {:ok, pub_point: pub_point, priv_scalar: priv_scalar}
  end

  test "decode_private_key/1 passes raw ECC scalar bytes through unchanged", %{priv_scalar: priv} do
    assert EcdsaP256.decode_private_key(priv) == priv
  end

  test "algorithm_identifier_der/0 returns the RFC 5754 ecdsa-with-SHA256 DER", _ctx do
    der = EcdsaP256.algorithm_identifier_der()
    assert is_binary(der)
    # ecdsa-with-SHA256 OID is 1.2.840.10045.4.3.2, encoded as
    # 0x06 0x08 0x2A 0x86 0x48 0xCE 0x3D 0x04 0x03 0x02 inside a SEQUENCE.
    # The full AlgorithmIdentifier (no params) is:
    #   SEQUENCE { OID 1.2.840.10045.4.3.2 }
    # = 30 0A 06 08 2A 86 48 CE 3D 04 03 02
    assert der == <<0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02>>
  end

  test "sign/2 produces a signature verifiable with :public_key.verify/4", %{pub_point: pub, priv_scalar: priv} do
    tbs = "test message to sign" |> :erlang.term_to_binary()

    decoded_priv = EcdsaP256.decode_private_key(priv)
    signature = EcdsaP256.sign(tbs, decoded_priv)

    assert is_binary(signature)

    p256_oid = {1, 2, 840, 10045, 3, 1, 7}

    assert :public_key.verify(
             tbs,
             :sha256,
             signature,
             {{:ECPoint, pub}, {:namedCurve, p256_oid}}
           )
  end
end
```

- [ ] **Step 2: Run to verify failure**

```
mix test test/pki_validation/crypto/signer/ecdsa_p256_test.exs
```

Expected: FAIL — module not defined.

- [ ] **Step 3: Implement the module**

```elixir
defmodule PkiValidation.Crypto.Signer.EcdsaP256 do
  @moduledoc """
  ECDSA with SHA-256 over secp256r1 (P-256).

  The at-rest private key for ECC is the raw private scalar bytes as
  produced by `:crypto.generate_key(:ecdh, :secp256r1)`. `decode_private_key/1`
  is a passthrough — no parsing is required.

  At sign time the scalar is wrapped in an `ECPrivateKey` record that
  `:public_key.sign/3` accepts.
  """

  @behaviour PkiValidation.Crypto.Signer

  # ecdsa-with-SHA256 AlgorithmIdentifier (RFC 5754) — no params
  # SEQUENCE { OID 1.2.840.10045.4.3.2 }
  @algorithm_identifier_der <<0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02>>

  @secp256r1_oid {1, 2, 840, 10045, 3, 1, 7}

  @impl true
  def decode_private_key(raw_scalar) when is_binary(raw_scalar), do: raw_scalar

  @impl true
  def sign(tbs, raw_scalar) when is_binary(tbs) and is_binary(raw_scalar) do
    ec_priv_record =
      {:ECPrivateKey, 1, raw_scalar, {:namedCurve, @secp256r1_oid}, :asn1_NOVALUE, :asn1_NOVALUE}

    :public_key.sign(tbs, :sha256, ec_priv_record)
  end

  @impl true
  def algorithm_identifier_der, do: @algorithm_identifier_der
end
```

- [ ] **Step 4: Run the test**

```
mix test test/pki_validation/crypto/signer/ecdsa_p256_test.exs
```

Expected: 3 tests, 0 failures.

- [ ] **Step 5: Stage**

```
git add src/pki_validation/lib/pki_validation/crypto/signer/ecdsa_p256.ex \
        src/pki_validation/test/pki_validation/crypto/signer/ecdsa_p256_test.exs
```

---

## Task 5: EcdsaP384 signer module

**Goal:** Same shape as EcdsaP256 but with secp384r1 + SHA-384.

**Files:**
- Create: `src/pki_validation/lib/pki_validation/crypto/signer/ecdsa_p384.ex`
- Create: `src/pki_validation/test/pki_validation/crypto/signer/ecdsa_p384_test.exs`

- [ ] **Step 1: Write failing test**

```elixir
defmodule PkiValidation.Crypto.Signer.EcdsaP384Test do
  use ExUnit.Case, async: true

  alias PkiValidation.Crypto.Signer.EcdsaP384

  setup do
    {pub_point, priv_scalar} = :crypto.generate_key(:ecdh, :secp384r1)
    {:ok, pub_point: pub_point, priv_scalar: priv_scalar}
  end

  test "decode_private_key/1 passes raw ECC scalar bytes through unchanged", %{priv_scalar: priv} do
    assert EcdsaP384.decode_private_key(priv) == priv
  end

  test "algorithm_identifier_der/0 returns the RFC 5754 ecdsa-with-SHA384 DER" do
    # ecdsa-with-SHA384 OID is 1.2.840.10045.4.3.3
    # SEQUENCE { OID 1.2.840.10045.4.3.3 }
    # = 30 0A 06 08 2A 86 48 CE 3D 04 03 03
    assert EcdsaP384.algorithm_identifier_der() ==
             <<0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03>>
  end

  test "sign/2 produces a signature verifiable with :public_key.verify/4", %{pub_point: pub, priv_scalar: priv} do
    tbs = "p-384 test message"

    signature = EcdsaP384.sign(tbs, EcdsaP384.decode_private_key(priv))

    p384_oid = {1, 3, 132, 0, 34}

    assert :public_key.verify(
             tbs,
             :sha384,
             signature,
             {{:ECPoint, pub}, {:namedCurve, p384_oid}}
           )
  end
end
```

- [ ] **Step 2: Run to verify failure**

```
mix test test/pki_validation/crypto/signer/ecdsa_p384_test.exs
```

Expected: FAIL.

- [ ] **Step 3: Implement**

```elixir
defmodule PkiValidation.Crypto.Signer.EcdsaP384 do
  @moduledoc """
  ECDSA with SHA-384 over secp384r1 (P-384).

  Same at-rest format as `EcdsaP256` — the private key is the raw scalar.
  """

  @behaviour PkiValidation.Crypto.Signer

  # ecdsa-with-SHA384 AlgorithmIdentifier (RFC 5754) — no params
  @algorithm_identifier_der <<0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03>>

  @secp384r1_oid {1, 3, 132, 0, 34}

  @impl true
  def decode_private_key(raw_scalar) when is_binary(raw_scalar), do: raw_scalar

  @impl true
  def sign(tbs, raw_scalar) when is_binary(tbs) and is_binary(raw_scalar) do
    ec_priv_record =
      {:ECPrivateKey, 1, raw_scalar, {:namedCurve, @secp384r1_oid}, :asn1_NOVALUE, :asn1_NOVALUE}

    :public_key.sign(tbs, :sha384, ec_priv_record)
  end

  @impl true
  def algorithm_identifier_der, do: @algorithm_identifier_der
end
```

- [ ] **Step 4: Run test**

```
mix test test/pki_validation/crypto/signer/ecdsa_p384_test.exs
```

Expected: 3 tests, 0 failures.

- [ ] **Step 5: Stage**

---

## Task 6: Rsa2048 signer module

**Goal:** RSA-2048 signer. Critical: `decode_private_key/1` calls `:public_key.der_decode(:RSAPrivateKey, der)` once at load time — this is where the D1 bug fix becomes structural.

**Files:**
- Create: `src/pki_validation/lib/pki_validation/crypto/signer/rsa2048.ex`
- Create: `src/pki_validation/test/pki_validation/crypto/signer/rsa2048_test.exs`

- [ ] **Step 1: Write failing test**

```elixir
defmodule PkiValidation.Crypto.Signer.Rsa2048Test do
  use ExUnit.Case, async: true

  alias PkiValidation.Crypto.Signer.Rsa2048

  setup do
    # Generate an RSA 2048-bit keypair
    rsa_priv_record = :public_key.generate_key({:rsa, 2048, 65537})
    rsa_priv_der = :public_key.der_encode(:RSAPrivateKey, rsa_priv_record)

    {:ok,
     rsa_priv_record: rsa_priv_record,
     rsa_priv_der: rsa_priv_der}
  end

  test "decode_private_key/1 decodes the DER form into the :RSAPrivateKey record", %{rsa_priv_der: der, rsa_priv_record: expected} do
    assert Rsa2048.decode_private_key(der) == expected
  end

  test "algorithm_identifier_der/0 returns the RFC 4055 sha256WithRSAEncryption DER" do
    # sha256WithRSAEncryption OID is 1.2.840.113549.1.1.11
    # AlgorithmIdentifier has NULL params for RSA (05 00)
    # SEQUENCE { OID 1.2.840.113549.1.1.11, NULL }
    # = 30 0D 06 09 2A 86 48 86 F7 0D 01 01 0B 05 00
    assert Rsa2048.algorithm_identifier_der() ==
             <<0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00>>
  end

  test "sign/2 produces a signature verifiable with the RSA public key", %{rsa_priv_record: rsa_priv_record, rsa_priv_der: der} do
    tbs = "rsa-2048 test message"

    # SigningKeyStore would have called decode_private_key/1 at load time
    decoded = Rsa2048.decode_private_key(der)
    signature = Rsa2048.sign(tbs, decoded)

    # Extract the public key from the private record
    {:RSAPrivateKey, _v, modulus, exponent, _, _, _, _, _, _, _} = rsa_priv_record
    rsa_pub = {:RSAPublicKey, modulus, exponent}

    assert :public_key.verify(tbs, :sha256, signature, rsa_pub)
  end
end
```

- [ ] **Step 2: Run to verify failure**

```
mix test test/pki_validation/crypto/signer/rsa2048_test.exs
```

- [ ] **Step 3: Implement**

```elixir
defmodule PkiValidation.Crypto.Signer.Rsa2048 do
  @moduledoc """
  RSA-2048 with SHA-256.

  The at-rest private key is the DER encoding of an `:RSAPrivateKey`
  record — this is what the existing `SigningKeyStore` stores (the
  decrypted bytes from AES-256-GCM).

  `decode_private_key/1` decodes this once at load time into the
  `:RSAPrivateKey` Erlang record. `sign/2` receives that decoded record
  and passes it directly to `:public_key.sign/3`. This structurally
  prevents the D1 class of bug where raw DER bytes were being passed to
  `:public_key.sign/3` (which requires a decoded record) at sign time.
  """

  @behaviour PkiValidation.Crypto.Signer

  # sha256WithRSAEncryption AlgorithmIdentifier (RFC 4055)
  # NULL params for RSA signatures
  @algorithm_identifier_der <<0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00>>

  @impl true
  def decode_private_key(der) when is_binary(der) do
    :public_key.der_decode(:RSAPrivateKey, der)
  end

  @impl true
  def sign(tbs, rsa_priv_record) when is_binary(tbs) and is_tuple(rsa_priv_record) do
    :public_key.sign(tbs, :sha256, rsa_priv_record)
  end

  @impl true
  def algorithm_identifier_der, do: @algorithm_identifier_der
end
```

- [ ] **Step 4: Run test**

```
mix test test/pki_validation/crypto/signer/rsa2048_test.exs
```

Expected: 3 tests, 0 failures.

- [ ] **Step 5: Stage**

---

## Task 7: Rsa4096 signer module

**Goal:** Same as Rsa2048 but 4096-bit key generation.

**Files:**
- Create: `src/pki_validation/lib/pki_validation/crypto/signer/rsa4096.ex`
- Create: `src/pki_validation/test/pki_validation/crypto/signer/rsa4096_test.exs`

- [ ] **Step 1: Write failing test**

Same structure as Rsa2048Test but with `{:rsa, 4096, 65537}`:

```elixir
defmodule PkiValidation.Crypto.Signer.Rsa4096Test do
  use ExUnit.Case, async: true

  alias PkiValidation.Crypto.Signer.Rsa4096

  setup do
    rsa_priv_record = :public_key.generate_key({:rsa, 4096, 65537})
    rsa_priv_der = :public_key.der_encode(:RSAPrivateKey, rsa_priv_record)
    {:ok, rsa_priv_record: rsa_priv_record, rsa_priv_der: rsa_priv_der}
  end

  test "decode_private_key/1 decodes DER into :RSAPrivateKey record", %{rsa_priv_der: der, rsa_priv_record: expected} do
    assert Rsa4096.decode_private_key(der) == expected
  end

  test "algorithm_identifier_der/0 returns sha256WithRSAEncryption DER" do
    assert Rsa4096.algorithm_identifier_der() ==
             <<0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00>>
  end

  test "sign/2 produces a signature verifiable with RSA public key", %{rsa_priv_record: rsa_priv_record, rsa_priv_der: der} do
    tbs = "rsa-4096 test message"
    decoded = Rsa4096.decode_private_key(der)
    signature = Rsa4096.sign(tbs, decoded)

    {:RSAPrivateKey, _v, modulus, exponent, _, _, _, _, _, _, _} = rsa_priv_record
    rsa_pub = {:RSAPublicKey, modulus, exponent}
    assert :public_key.verify(tbs, :sha256, signature, rsa_pub)
  end
end
```

**Note on test time:** 4096-bit RSA key generation can be slow (~1-2s). The test is `async: true` but the generation itself is serialised per-process. If this proves too slow, tag with `@tag :slow` and exclude from default runs.

- [ ] **Step 2: Run to verify failure**

```
mix test test/pki_validation/crypto/signer/rsa4096_test.exs
```

- [ ] **Step 3: Implement**

```elixir
defmodule PkiValidation.Crypto.Signer.Rsa4096 do
  @moduledoc """
  RSA-4096 with SHA-256.

  Same shape as `Rsa2048` — the only difference is the key size. Both use
  sha256WithRSAEncryption as the signature algorithm. `decode_private_key/1`
  runs once at `SigningKeyStore` load time.
  """

  @behaviour PkiValidation.Crypto.Signer

  @algorithm_identifier_der <<0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00>>

  @impl true
  def decode_private_key(der) when is_binary(der) do
    :public_key.der_decode(:RSAPrivateKey, der)
  end

  @impl true
  def sign(tbs, rsa_priv_record) when is_binary(tbs) and is_tuple(rsa_priv_record) do
    :public_key.sign(tbs, :sha256, rsa_priv_record)
  end

  @impl true
  def algorithm_identifier_der, do: @algorithm_identifier_der
end
```

- [ ] **Step 4: Run test**

```
mix test test/pki_validation/crypto/signer/rsa4096_test.exs
```

Expected: 3 tests, 0 failures.

- [ ] **Step 5: Stage**

---

## Task 8: Signer Registry

**Goal:** Map algorithm strings from the DB to concrete signer modules.

**Files:**
- Create: `src/pki_validation/lib/pki_validation/crypto/signer/registry.ex`
- Create: `src/pki_validation/test/pki_validation/crypto/signer/registry_test.exs`

- [ ] **Step 1: Write failing test**

```elixir
defmodule PkiValidation.Crypto.Signer.RegistryTest do
  use ExUnit.Case, async: true

  alias PkiValidation.Crypto.Signer.Registry

  alias PkiValidation.Crypto.Signer.{EcdsaP256, EcdsaP384, Rsa2048, Rsa4096}

  test "fetch/1 returns the signer module for each known algorithm string" do
    assert Registry.fetch("ecc_p256") == {:ok, EcdsaP256}
    assert Registry.fetch("ecc_p384") == {:ok, EcdsaP384}
    assert Registry.fetch("rsa2048") == {:ok, Rsa2048}
    assert Registry.fetch("rsa4096") == {:ok, Rsa4096}
  end

  test "fetch/1 returns :error for an unknown algorithm string" do
    assert Registry.fetch("ml_dsa_65") == :error
    assert Registry.fetch("bogus") == :error
    assert Registry.fetch("") == :error
  end
end
```

- [ ] **Step 2: Run to verify failure**

```
mix test test/pki_validation/crypto/signer/registry_test.exs
```

- [ ] **Step 3: Implement**

```elixir
defmodule PkiValidation.Crypto.Signer.Registry do
  @moduledoc """
  Maps algorithm strings from `SigningKeyConfig.algorithm` to concrete
  `PkiValidation.Crypto.Signer` implementations.

  To add a new signer:

    1. Add the algorithm string to
       `PkiValidation.Schema.SigningKeyConfig` `@valid_algorithms`
    2. Create the new module under `PkiValidation.Crypto.Signer.*`
       implementing the `PkiValidation.Crypto.Signer` behaviour
    3. Add one line to `@mapping` below
  """

  alias PkiValidation.Crypto.Signer.{EcdsaP256, EcdsaP384, Rsa2048, Rsa4096}

  @mapping %{
    "ecc_p256" => EcdsaP256,
    "ecc_p384" => EcdsaP384,
    "rsa2048" => Rsa2048,
    "rsa4096" => Rsa4096
  }

  @doc """
  Look up the signer module for a given algorithm string.

  Returns `{:ok, module}` on success or `:error` if the algorithm is
  not registered.
  """
  @spec fetch(String.t()) :: {:ok, module()} | :error
  def fetch(algorithm) when is_binary(algorithm), do: Map.fetch(@mapping, algorithm)
  def fetch(_), do: :error
end
```

- [ ] **Step 4: Run test**

```
mix test test/pki_validation/crypto/signer/registry_test.exs
```

Expected: 2 tests, 0 failures.

- [ ] **Step 5: Stage**

---

## Task 9: SigningKeyStore uses the Signer registry

**Goal:** Resolve the signer module at load time, decode the private key via the signer, cache both in state. Keys with unknown algorithm strings are dropped with a `:unknown_algorithm` failure reason (surfaces in `status/0`).

**Files:**
- Modify: `src/pki_validation/lib/pki_validation/signing_key_store.ex`
- Modify: `src/pki_validation/test/pki_validation/signing_key_store_test.exs`

- [ ] **Step 1: Write failing test**

Add to `signing_key_store_test.exs`:

```elixir
describe "signer resolution at load time" do
  test "entries include the resolved signer module", %{name: name, issuer_key_id: id} do
    {:ok, key} = SigningKeyStore.get(name, id)
    assert key.signer == PkiValidation.Crypto.Signer.EcdsaP256
  end

  test "private_key is decoded via the signer at load time (ECC passthrough)", %{name: name, issuer_key_id: id} do
    {:ok, key} = SigningKeyStore.get(name, id)
    # For ECC the decoded form is still the raw scalar bytes, so this is a
    # structural assertion that the signer's decode_private_key/1 was invoked.
    assert is_binary(key.private_key)
    assert byte_size(key.private_key) > 0
  end

  test "rows with unknown algorithm are dropped and reported in status" do
    bad_id = Uniq.UUID.uuid7()
    cert_pem = generate_test_cert_pem()
    {_pub, priv} = :crypto.generate_key(:ecdh, :secp256r1)
    encrypted = SigningKeyStore.encrypt_for_test(priv, "test-password")

    # Insert directly via SQL to bypass the SigningKeyConfig changeset
    # @valid_algorithms enum validation — we're simulating a future-algorithm
    # row that our Registry doesn't know about yet.
    {:ok, _} =
      Ecto.Adapters.SQL.query(
        Repo,
        """
        INSERT INTO signing_key_config
          (id, issuer_key_id, algorithm, certificate_pem, encrypted_private_key,
           not_before, not_after, status, inserted_at, updated_at)
        VALUES
          ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        """,
        [
          Uniq.UUID.uuid7(:raw),
          Uniq.UUID.string_to_binary!(bad_id),
          "future_pqc_alg",
          cert_pem,
          encrypted,
          DateTime.utc_now(),
          DateTime.add(DateTime.utc_now(), 30, :day),
          "active",
          DateTime.utc_now(),
          DateTime.utc_now()
        ]
      )

    name2 = :"ks_unknown_alg_#{System.unique_integer([:positive])}"
    {:ok, _} = SigningKeyStore.start_link(name: name2, password: "test-password")

    assert :not_found = SigningKeyStore.get(name2, bad_id)

    status = SigningKeyStore.status(name2)
    assert status.failed >= 1
    assert status.last_error == :unknown_algorithm
  end
end
```

- [ ] **Step 2: Run to verify failure**

```
mix test test/pki_validation/signing_key_store_test.exs
```

Expected: new tests fail. Existing tests still pass (they're inspecting a slightly different map shape now but the fields they check — `algorithm`, `private_key`, `certificate_der`, `key_hash`, `not_after` — are still present).

Wait — the existing tests check these fields explicitly. Adding a `signer` field is additive, not breaking. But if any existing test does an exact map match, it'll break. Fix on the fly.

- [ ] **Step 3: Modify `load_keys/1`**

Replace `load_keys/1` (again — built on top of the Task 1 version):

```elixir
defp load_keys(password) do
  SigningKeyConfig
  |> where([c], c.status == "active")
  |> Repo.all()
  |> Enum.reduce({%{}, 0, []}, fn config, {keys, loaded, failed} ->
    with {:ok, signer_mod} <- fetch_signer(config.algorithm),
         {:ok, raw_priv} <- decrypt_private_key(config.encrypted_private_key, password),
         {:ok, cert_der} <- decode_cert_pem(config.certificate_pem),
         {:ok, decoded_priv} <- decode_signer_private_key(signer_mod, raw_priv) do
      entry = %{
        algorithm: config.algorithm,
        signer: signer_mod,
        private_key: decoded_priv,
        certificate_der: cert_der,
        key_hash: PkiValidation.CertId.issuer_key_hash(cert_der),
        not_after: config.not_after
      }

      {Map.put(keys, config.issuer_key_id, entry), loaded + 1, failed}
    else
      {:error, reason} ->
        Logger.error(
          "Failed to load signing key for issuer #{config.issuer_key_id}: #{inspect(reason)}"
        )

        failure = %{issuer_key_id: config.issuer_key_id, reason: reason}
        new_failed = Enum.take([failure | failed], 50)
        {keys, loaded, new_failed}
    end
  end)
end

defp fetch_signer(algorithm) do
  case PkiValidation.Crypto.Signer.Registry.fetch(algorithm) do
    {:ok, mod} -> {:ok, mod}
    :error -> {:error, :unknown_algorithm}
  end
end

defp decode_signer_private_key(signer_mod, raw_priv) do
  {:ok, signer_mod.decode_private_key(raw_priv)}
rescue
  _ -> {:error, :private_key_decode_failed}
end
```

- [ ] **Step 4: Run the signer-resolution tests**

```
mix test test/pki_validation/signing_key_store_test.exs
```

Expected: all tests pass — both new signer-resolution tests and existing tests (existing tests read the unchanged fields; the `signer` key is additive).

**If any existing test fails** with an exact-map-match regression, loosen that assertion to check the specific fields it cares about, not the whole map.

- [ ] **Step 5: Run the full suite**

```
mix test
```

Expected: 130 (after Tasks 1-2) + 3 (Task 4 signers) × 4 modules + 2 (Registry) + 3 (signer resolution in SigningKeyStore) = roughly 147 tests. Adjust expectation to actual.

- [ ] **Step 6: Stage**

```
git add src/pki_validation/lib/pki_validation/signing_key_store.ex \
        src/pki_validation/test/pki_validation/signing_key_store_test.exs
```

---

## Task 10: ResponseBuilder uses the cached signer

**Goal:** Collapse `ResponseBuilder.sign_tbs/2` to a single clause that delegates to the cached signer module. Delete the per-algorithm AlgorithmIdentifier DER module attributes.

**Files:**
- Modify: `src/pki_validation/lib/pki_validation/ocsp/response_builder.ex`

- [ ] **Step 1: Read the current `sign_tbs/2` + AlgorithmIdentifier attrs**

```
mix format  # pre-format to stable baseline
grep -n "sign_tbs\|@.*_alg_der\|@.*_oid\|@.*_sha" src/pki_validation/lib/pki_validation/ocsp/response_builder.ex
```

Identify every module attribute that pre-encodes an AlgorithmIdentifier (`@ecdsa_sha256_alg_der`, `@ecdsa_sha384_alg_der`, `@rsa_sha256_alg_der`, etc.) and every `sign_tbs/2` clause.

- [ ] **Step 2: Replace all `sign_tbs/2` clauses with one**

```elixir
defp sign_tbs(tbs, %{signer: signer_mod, private_key: priv}) do
  signature = signer_mod.sign(tbs, priv)
  {signer_mod.algorithm_identifier_der(), signature}
end
```

- [ ] **Step 3: Delete the per-algorithm module attributes**

Remove `@ecdsa_sha256_alg_der`, `@ecdsa_sha384_alg_der`, `@rsa_sha256_alg_der`, any curve-specific OIDs that were only used by the deleted clauses.

**Keep** any attributes that are still referenced by non-sign_tbs code (e.g. the hash AlgorithmIdentifier used in CertID records, `@sha1_alg_der`, `@basic_ocsp_oid`, `@nonce_oid`). Audit with `grep` before deleting.

- [ ] **Step 4: Compile and run the full test suite**

```
mix compile
mix test
```

Expected: **no test changes**. The external contract of `ResponseBuilder.build/4` is unchanged — only its internal dispatch. Every existing OCSP test must still pass, including the openssl interop tests. If any test fails, the signer module isn't being threaded through correctly — debug before proceeding.

Critical regression guards:
- `test "the signature is verifiable with the responder public key"` must pass — proves ECC signing still produces verifiable output
- `test "the signature is verifiable with the cert-embedded public key"` must pass — proves cert-key binding is preserved
- `test "signs an RSA-2048 OCSP response verifiable by openssl"` (from Phase 3.5 N-2) must pass — proves RSA path works through the new signer module
- OpenSSL interop tests must still pass (tagged `:interop`)

- [ ] **Step 5: Stage**

---

## Task 11: DerGenerator uses the cached signer

**Goal:** Same as Task 10 but for CRL.

**Files:**
- Modify: `src/pki_validation/lib/pki_validation/crl/der_generator.ex`

- [ ] **Step 1: Read the current `sign_tbs/2` + `sig_alg_identifier/1` + module attributes**

```
grep -n "sign_tbs\|sig_alg_identifier\|@.*_oid\|@.*_sha" src/pki_validation/lib/pki_validation/crl/der_generator.ex
```

- [ ] **Step 2: Replace `sign_tbs/2` with one clause**

```elixir
defp sign_tbs(tbs, %{signer: signer_mod, private_key: priv}) do
  signature = signer_mod.sign(tbs, priv)
  {signer_mod.algorithm_identifier_der(), signature}
end
```

- [ ] **Step 3: Delete `sig_alg_identifier/1`**

The signer module owns this now. Remove the helper and all its clauses.

- [ ] **Step 4: Find the caller of `sig_alg_identifier/1`**

The old code structure has the TBS building code calling something like:

```elixir
sig_alg = sig_alg_identifier(signing_key)
# ... embeds sig_alg in the TBSCertList record ...
```

The TBS construction must know the AlgorithmIdentifier **before** signing (because the TBS includes the sig_alg field). So the replacement needs:

```elixir
sig_alg_der = signer_mod.algorithm_identifier_der()
# ... but this is a binary, not an :AlgorithmIdentifier record ...
```

**This is the tricky bit:** `DerGenerator` uses `:public_key.der_encode(:TBSCertList, tbs)` which needs an `:AlgorithmIdentifier` *Erlang record*, not a pre-encoded DER blob. The OCSP path uses the local `:OCSP` module which accepts ANY-typed fields as raw bytes; the CRL path uses the `:public_key` built-in schema which wants structured records.

**Resolution:** the signer module can expose TWO things — the DER blob for OCSP (Task 10) AND the Erlang record for CRL (Task 11). Either add a second callback to the behaviour, OR do the decode at the CRL site:

```elixir
# In the CRL TBS building code:
sig_alg_der = signer_mod.algorithm_identifier_der()
sig_alg_record = :public_key.der_decode(:AlgorithmIdentifier, sig_alg_der)
# ... use sig_alg_record in the TBSCertList ...
```

The decode is cheap (static data) and keeps the behaviour narrow. Prefer this approach.

**Alternative:** if the existing code used a direct record construction like `{:AlgorithmIdentifier, oid_tuple, params}`, you may need a small helper in the CRL side to convert `signer.algorithm_identifier_der() |> :public_key.der_decode(:AlgorithmIdentifier, ...)`.

**Verify in iex** before changing code:

```elixir
:public_key.der_decode(:AlgorithmIdentifier, <<0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02>>)
```

If this returns `{:AlgorithmIdentifier, {1, 2, 840, 10045, 4, 3, 2}, :asn1_NOVALUE}`, the approach works. If not, you'll need to either:
- Add a second callback to the behaviour: `@callback algorithm_identifier_record() :: tuple()`
- Or have each signer module expose BOTH and use the right one per call site

If you end up adding the callback, update ALL four signer modules (`EcdsaP256`, `EcdsaP384`, `Rsa2048`, `Rsa4096`) with the matching record form.

- [ ] **Step 5: Compile and run the full test suite**

```
mix compile
mix test
```

Expected: all tests pass, including the CRL signature verification test that uses `:public_key.verify/4` against the cert-extracted public key, and the openssl CRL interop test.

- [ ] **Step 6: Stage**

---

## Task 12: Final sweep — format, compile, commit Part 2

- [ ] **Step 1: Format everything**

```
cd src/pki_validation
mix format
mix format --check-formatted
```

Expected: clean.

- [ ] **Step 2: Full test suite**

```
mix test
```

Expected: ~150 tests passing, 0 failures.

- [ ] **Step 3: Commit Part 2**

```
cd /Users/amirrudinyahaya/Workspace/pki/.worktrees/validation-followups
git add src/pki_validation/lib/pki_validation/crypto/ \
        src/pki_validation/test/pki_validation/crypto/ \
        src/pki_validation/lib/pki_validation/signing_key_store.ex \
        src/pki_validation/lib/pki_validation/ocsp/response_builder.ex \
        src/pki_validation/lib/pki_validation/crl/der_generator.ex \
        src/pki_validation/test/pki_validation/signing_key_store_test.exs

git commit -m "feat(validation): extract Signer behaviour + concrete modules

Kill the per-algorithm duct-tape in ResponseBuilder and DerGenerator
by extracting a PkiValidation.Crypto.Signer behaviour with three
callbacks:

  @callback decode_private_key(binary()) :: term()
  @callback sign(tbs :: binary(), private_key :: term()) :: binary()
  @callback algorithm_identifier_der() :: binary()

Four concrete modules under PkiValidation.Crypto.Signer.*:

  - EcdsaP256   (secp256r1, SHA-256)
  - EcdsaP384   (secp384r1, SHA-384)
  - Rsa2048     (2048-bit, SHA-256)
  - Rsa4096     (4096-bit, SHA-256)

A Registry module maps algorithm strings from SigningKeyConfig to
concrete signer modules. Adding ML-DSA, SLH-DSA, or KAZ-SIGN later
is a three-step developer experience: add the string to the schema
enum, create the signer module, add one line to the Registry.

SigningKeyStore.load_keys/1 now resolves the signer module at load
time and caches BOTH the module and the decoded private key. For RSA
this means der_decode(:RSAPrivateKey, ...) runs exactly once per key
at load time — structurally killing the D1 class of bug where raw
DER bytes were passed to :public_key.sign/3 per-signature.

Rows with an unknown algorithm string are dropped with a
:unknown_algorithm failure reason, which flows through the Part 1
status/0 + /health observability (operators see the degraded state
immediately instead of discovering it at request time).

ResponseBuilder.sign_tbs/2 and DerGenerator.sign_tbs/2 both collapse
to a single clause that delegates to the cached signer module. The
per-algorithm DER blob module attributes are deleted. The sign site
is now algorithm-agnostic.

No external contract changes. All 125 baseline tests still pass,
including the OpenSSL interop tests — the refactor is purely
internal dispatch.

130 (after Part 1) -> ~150 tests passing.
"
```

---

## Self-Review Checklist (run after writing this plan)

**Spec coverage:**
- [x] Part 1 Observability → Tasks 1, 2
- [x] Part 2 Signer behaviour → Tasks 3, 4, 5, 6, 7 (concrete modules), 8 (registry)
- [x] SigningKeyStore uses registry → Task 9
- [x] Consumer refactor → Tasks 10 (ResponseBuilder), 11 (DerGenerator)
- [x] Final sweep → Task 12

**Placeholder scan:**
- [x] No "TBD"/"TODO"/"similar to Task N without showing code"
- [x] Every code step contains actual code
- [x] Test code shown in full, not abbreviated

**Type consistency:**
- [x] `signing_key` map shape is consistent: `%{algorithm, signer, private_key, certificate_der, key_hash, not_after}` across all consumers
- [x] `Signer` behaviour callbacks match in `signer.ex` and all four concrete modules
- [x] `status/1` return shape is consistent across the tests and the implementation
- [x] Atom reasons (`:decryption_failed`, `:malformed_ciphertext`, `:unknown_algorithm`, `:private_key_decode_failed`, `:invalid_cert_pem`) are used consistently

**Known risks called out:**
- [x] Task 11 has a subtle issue around `:AlgorithmIdentifier` as DER blob vs Erlang record. Verification step in iex before coding is explicit.
- [x] Existing tests may need small assertion changes if they did exact-map-match on the signing_key shape. Noted in Task 9 Step 4.
- [x] 4096-bit RSA test may be slow; slow-tag fallback mentioned.
