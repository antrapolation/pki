# PkiCrypto Shared Library — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create a protocol-based cryptographic library (`pki_crypto`) that all PKI services depend on for algorithm dispatch, key operations, and Shamir secret sharing.

**Architecture:** Elixir protocol `PkiCrypto.Algorithm` dispatches on struct type. Each algorithm (RSA-4096, ECC-P256, ECDH-P256) is a struct with a `defimpl`. A registry maps string names to structs. Shamir splitting and symmetric encryption are standalone utility modules. This replaces the existing `PkiCaEngine.KeyCeremony.CryptoAdapter` protocol.

**Tech Stack:** Elixir, Erlang `:public_key` + `:crypto`, `keyx` (Shamir), `uniq` (UUIDv7)

**Spec:** `docs/superpowers/specs/2026-03-26-beta2-multi-tenancy-crypto-credentials.md` Section 12

---

## File Structure

```
src/pki_crypto/
├── mix.exs
├── lib/
│   └── pki_crypto/
│       ├── algorithm.ex                — protocol definition
│       ├── signing/
│       │   ├── rsa4096.ex              — RSA-4096 struct + impl
│       │   ├── ecc_p256.ex             — ECC-P256 struct + impl
│       │   └── ecc_p384.ex             — ECC-P384 struct + impl
│       ├── kem/
│       │   └── ecdh_p256.ex            — ECDH-P256 struct + impl
│       ├── symmetric.ex                — AES-256-GCM encrypt/decrypt
│       ├── kdf.ex                      — HKDF-SHA-256 key derivation
│       ├── shamir.ex                   — Shamir secret sharing (split/recover)
│       └── registry.ex                 — algorithm name ↔ struct lookup
└── test/
    ├── test_helper.exs
    ├── pki_crypto/
    │   ├── algorithm_shared_test.exs   — shared test suite all impls must pass
    │   ├── signing/
    │   │   ├── rsa4096_test.exs
    │   │   ├── ecc_p256_test.exs
    │   │   └── ecc_p384_test.exs
    │   ├── kem/
    │   │   └── ecdh_p256_test.exs
    │   ├── symmetric_test.exs
    │   ├── kdf_test.exs
    │   ├── shamir_test.exs
    │   └── registry_test.exs
    └── support/
```

---

### Task 1: Create mix project skeleton

**Files:**
- Create: `src/pki_crypto/mix.exs`
- Create: `src/pki_crypto/lib/pki_crypto.ex`
- Create: `src/pki_crypto/test/test_helper.exs`

- [ ] **Step 1: Create mix project**

```bash
cd src
mkdir -p pki_crypto/lib/pki_crypto pki_crypto/test/pki_crypto
```

- [ ] **Step 2: Write mix.exs**

```elixir
# src/pki_crypto/mix.exs
defmodule PkiCrypto.MixProject do
  use Mix.Project

  def project do
    [
      app: :pki_crypto,
      version: "0.1.0",
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      elixirc_paths: elixirc_paths(Mix.env())
    ]
  end

  def application do
    [extra_applications: [:logger, :crypto, :public_key]]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:keyx, path: "../keyx"},
      {:uniq, "~> 0.6"}
    ]
  end
end
```

- [ ] **Step 3: Write root module**

```elixir
# src/pki_crypto/lib/pki_crypto.ex
defmodule PkiCrypto do
  @moduledoc "Protocol-based cryptographic library for the PKI system."
end
```

- [ ] **Step 4: Write test helper**

```elixir
# src/pki_crypto/test/test_helper.exs
ExUnit.start()
```

- [ ] **Step 5: Verify project compiles**

```bash
cd src/pki_crypto && mix deps.get && mix compile
```

Expected: Compiles with 0 errors

- [ ] **Step 6: Commit**

```bash
git add src/pki_crypto/
git commit -m "feat(pki_crypto): create mix project skeleton"
```

---

### Task 2: Define PkiCrypto.Algorithm protocol

**Files:**
- Create: `src/pki_crypto/lib/pki_crypto/algorithm.ex`
- Create: `src/pki_crypto/test/pki_crypto/algorithm_shared_test.exs`

- [ ] **Step 1: Write the protocol**

```elixir
# src/pki_crypto/lib/pki_crypto/algorithm.ex
defprotocol PkiCrypto.Algorithm do
  @moduledoc """
  Protocol for cryptographic algorithm dispatch.

  Each algorithm (RSA, ECC, KEM variants) implements this protocol
  via a struct. Dispatch is automatic based on the struct type.
  """

  @doc "Generate a keypair. Returns {:ok, %{public_key: binary, private_key: binary}} or {:error, reason}"
  def generate_keypair(algorithm)

  @doc "Sign data. Returns {:ok, signature_binary} or {:error, reason}"
  def sign(algorithm, private_key, data)

  @doc "Verify signature. Returns :ok or {:error, :invalid_signature}"
  def verify(algorithm, public_key, signature, data)

  @doc "KEM encapsulate. Returns {:ok, {shared_secret, ciphertext}} or {:error, :not_supported}"
  def kem_encapsulate(algorithm, public_key)

  @doc "KEM decapsulate. Returns {:ok, shared_secret} or {:error, reason}"
  def kem_decapsulate(algorithm, private_key, ciphertext)

  @doc "Algorithm identifier string for DB storage and wire format"
  def identifier(algorithm)

  @doc "Algorithm type — :signing, :kem, or :dual"
  def algorithm_type(algorithm)
end
```

- [ ] **Step 2: Write shared test module (tests every impl must pass)**

```elixir
# src/pki_crypto/test/pki_crypto/algorithm_shared_test.exs
defmodule PkiCrypto.AlgorithmSharedTest do
  @moduledoc """
  Shared test suite that every PkiCrypto.Algorithm implementation must pass.
  Import this in each algorithm's test module.
  """

  defmacro __using__(opts) do
    algorithm = Keyword.fetch!(opts, :algorithm)

    quote do
      alias PkiCrypto.Algorithm

      describe "#{inspect(unquote(algorithm))} protocol compliance" do
        test "identifier returns a non-empty string" do
          algo = unquote(algorithm)
          id = Algorithm.identifier(algo)
          assert is_binary(id)
          assert byte_size(id) > 0
        end

        test "algorithm_type returns :signing, :kem, or :dual" do
          algo = unquote(algorithm)
          assert Algorithm.algorithm_type(algo) in [:signing, :kem, :dual]
        end

        test "generate_keypair returns {:ok, %{public_key, private_key}}" do
          algo = unquote(algorithm)
          assert {:ok, %{public_key: pub, private_key: priv}} = Algorithm.generate_keypair(algo)
          assert is_binary(pub)
          assert is_binary(priv)
          assert byte_size(pub) > 0
          assert byte_size(priv) > 0
        end

        test "generate_keypair produces different keys each time" do
          algo = unquote(algorithm)
          {:ok, kp1} = Algorithm.generate_keypair(algo)
          {:ok, kp2} = Algorithm.generate_keypair(algo)
          assert kp1.private_key != kp2.private_key
        end
      end

      if Algorithm.algorithm_type(unquote(algorithm)) in [:signing, :dual] do
        describe "#{inspect(unquote(algorithm))} signing" do
          test "sign then verify round-trip" do
            algo = unquote(algorithm)
            {:ok, %{public_key: pub, private_key: priv}} = Algorithm.generate_keypair(algo)
            data = :crypto.strong_rand_bytes(64)

            {:ok, sig} = Algorithm.sign(algo, priv, data)
            assert is_binary(sig)
            assert :ok = Algorithm.verify(algo, pub, sig, data)
          end

          test "verify rejects wrong data" do
            algo = unquote(algorithm)
            {:ok, %{public_key: pub, private_key: priv}} = Algorithm.generate_keypair(algo)
            data = :crypto.strong_rand_bytes(64)
            wrong_data = :crypto.strong_rand_bytes(64)

            {:ok, sig} = Algorithm.sign(algo, priv, data)
            assert {:error, :invalid_signature} = Algorithm.verify(algo, pub, sig, wrong_data)
          end

          test "verify rejects wrong key" do
            algo = unquote(algorithm)
            {:ok, %{public_key: _pub1, private_key: priv}} = Algorithm.generate_keypair(algo)
            {:ok, %{public_key: pub2, private_key: _priv2}} = Algorithm.generate_keypair(algo)
            data = :crypto.strong_rand_bytes(64)

            {:ok, sig} = Algorithm.sign(algo, priv, data)
            assert {:error, :invalid_signature} = Algorithm.verify(algo, pub2, sig, data)
          end
        end
      end

      if Algorithm.algorithm_type(unquote(algorithm)) in [:kem, :dual] do
        describe "#{inspect(unquote(algorithm))} KEM" do
          test "encapsulate then decapsulate round-trip" do
            algo = unquote(algorithm)
            {:ok, %{public_key: pub, private_key: priv}} = Algorithm.generate_keypair(algo)

            {:ok, {shared_secret_enc, ciphertext}} = Algorithm.kem_encapsulate(algo, pub)
            {:ok, shared_secret_dec} = Algorithm.kem_decapsulate(algo, priv, ciphertext)

            assert shared_secret_enc == shared_secret_dec
            assert byte_size(shared_secret_enc) >= 16
          end

          test "decapsulate with wrong key fails" do
            algo = unquote(algorithm)
            {:ok, %{public_key: pub, private_key: _priv1}} = Algorithm.generate_keypair(algo)
            {:ok, %{public_key: _pub2, private_key: priv2}} = Algorithm.generate_keypair(algo)

            {:ok, {_ss, ciphertext}} = Algorithm.kem_encapsulate(algo, pub)
            result = Algorithm.kem_decapsulate(algo, priv2, ciphertext)
            # Either error or different shared secret (depending on algorithm)
            case result do
              {:error, _} -> :ok
              {:ok, ss} -> assert ss != elem(Algorithm.kem_encapsulate(algo, pub), 1) |> elem(0)
            end
          end
        end
      end
    end
  end
end
```

- [ ] **Step 3: Verify compiles**

```bash
mix compile
```

Expected: Compiles (protocol defined, no implementations yet)

- [ ] **Step 4: Commit**

```bash
git add src/pki_crypto/lib/pki_crypto/algorithm.ex src/pki_crypto/test/pki_crypto/algorithm_shared_test.exs
git commit -m "feat(pki_crypto): define Algorithm protocol and shared test suite"
```

---

### Task 3: Implement RSA-4096 signing algorithm

**Files:**
- Create: `src/pki_crypto/lib/pki_crypto/signing/rsa4096.ex`
- Create: `src/pki_crypto/test/pki_crypto/signing/rsa4096_test.exs`

- [ ] **Step 1: Write the failing test**

```elixir
# src/pki_crypto/test/pki_crypto/signing/rsa4096_test.exs
defmodule PkiCrypto.Signing.RSA4096Test do
  use ExUnit.Case, async: true
  use PkiCrypto.AlgorithmSharedTest, algorithm: %PkiCrypto.Signing.RSA4096{}

  test "identifier is RSA-4096" do
    assert PkiCrypto.Algorithm.identifier(%PkiCrypto.Signing.RSA4096{}) == "RSA-4096"
  end

  test "algorithm_type is :signing" do
    assert PkiCrypto.Algorithm.algorithm_type(%PkiCrypto.Signing.RSA4096{}) == :signing
  end

  test "KEM operations return :not_supported" do
    algo = %PkiCrypto.Signing.RSA4096{}
    assert {:error, :not_supported} = PkiCrypto.Algorithm.kem_encapsulate(algo, "key")
    assert {:error, :not_supported} = PkiCrypto.Algorithm.kem_decapsulate(algo, "key", "ct")
  end

  test "private key is DER-encoded" do
    algo = %PkiCrypto.Signing.RSA4096{}
    {:ok, %{private_key: priv}} = PkiCrypto.Algorithm.generate_keypair(algo)
    assert {:ok, _} = safe_der_decode(priv)
  end

  defp safe_der_decode(der) do
    {:ok, :public_key.der_decode(:RSAPrivateKey, der)}
  rescue
    _ -> {:error, :not_der}
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

```bash
mix test test/pki_crypto/signing/rsa4096_test.exs
```

Expected: FAIL — module `PkiCrypto.Signing.RSA4096` not found

- [ ] **Step 3: Write implementation**

```elixir
# src/pki_crypto/lib/pki_crypto/signing/rsa4096.ex
defmodule PkiCrypto.Signing.RSA4096 do
  @moduledoc "RSA-4096 signing algorithm."
  defstruct []
end

defimpl PkiCrypto.Algorithm, for: PkiCrypto.Signing.RSA4096 do
  def generate_keypair(_algo) do
    {pub, priv} = :public_key.generate_key({:rsa, 4096, 65537})
    {:ok, %{
      public_key: :public_key.der_encode(:RSAPublicKey, pub),
      private_key: :public_key.der_encode(:RSAPrivateKey, priv)
    }}
  rescue
    e -> {:error, Exception.message(e)}
  end

  def sign(_algo, private_key_der, data) do
    priv = :public_key.der_decode(:RSAPrivateKey, private_key_der)
    sig = :public_key.sign(data, :sha256, priv)
    {:ok, sig}
  rescue
    e -> {:error, Exception.message(e)}
  end

  def verify(_algo, public_key_der, signature, data) do
    pub = :public_key.der_decode(:RSAPublicKey, public_key_der)
    if :public_key.verify(data, :sha256, signature, pub) do
      :ok
    else
      {:error, :invalid_signature}
    end
  rescue
    _ -> {:error, :invalid_signature}
  end

  def kem_encapsulate(_algo, _public_key), do: {:error, :not_supported}
  def kem_decapsulate(_algo, _private_key, _ciphertext), do: {:error, :not_supported}

  def identifier(_algo), do: "RSA-4096"
  def algorithm_type(_algo), do: :signing
end
```

- [ ] **Step 4: Run test to verify it passes**

```bash
mix test test/pki_crypto/signing/rsa4096_test.exs -v
```

Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/pki_crypto/lib/pki_crypto/signing/rsa4096.ex src/pki_crypto/test/pki_crypto/signing/rsa4096_test.exs
git commit -m "feat(pki_crypto): implement RSA-4096 signing algorithm"
```

---

### Task 4: Implement ECC-P256 and ECC-P384 signing algorithms

**Files:**
- Create: `src/pki_crypto/lib/pki_crypto/signing/ecc_p256.ex`
- Create: `src/pki_crypto/lib/pki_crypto/signing/ecc_p384.ex`
- Create: `src/pki_crypto/test/pki_crypto/signing/ecc_p256_test.exs`
- Create: `src/pki_crypto/test/pki_crypto/signing/ecc_p384_test.exs`

- [ ] **Step 1: Write failing tests for ECC-P256**

Same pattern as RSA4096 test but with `%PkiCrypto.Signing.ECCP256{}`, identifier `"ECC-P256"`.

- [ ] **Step 2: Write failing tests for ECC-P384**

Same pattern with `%PkiCrypto.Signing.ECCP384{}`, identifier `"ECC-P384"`.

- [ ] **Step 3: Run tests — both fail**

```bash
mix test test/pki_crypto/signing/ecc_p256_test.exs test/pki_crypto/signing/ecc_p384_test.exs
```

- [ ] **Step 4: Implement ECC-P256**

Use `:crypto.generate_key(:ecdh, :secp256r1)` for key generation, `:public_key.sign/3` with `:sha256` for signing. DER encode via `:public_key.der_encode(:ECPrivateKey, ...)`.

- [ ] **Step 5: Implement ECC-P384**

Same pattern with `:secp384r1` and `:sha384`.

- [ ] **Step 6: Run tests — all pass**

```bash
mix test test/pki_crypto/signing/ -v
```

- [ ] **Step 7: Commit**

```bash
git add src/pki_crypto/lib/pki_crypto/signing/ src/pki_crypto/test/pki_crypto/signing/
git commit -m "feat(pki_crypto): implement ECC-P256 and ECC-P384 signing algorithms"
```

---

### Task 5: Implement ECDH-P256 KEM algorithm

**Files:**
- Create: `src/pki_crypto/lib/pki_crypto/kem/ecdh_p256.ex`
- Create: `src/pki_crypto/test/pki_crypto/kem/ecdh_p256_test.exs`

- [ ] **Step 1: Write failing test**

Uses shared test suite with `algorithm: %PkiCrypto.Kem.ECDHP256{}`. Additional tests: identifier is `"ECDH-P256"`, type is `:kem`, sign operations return `:not_supported`.

- [ ] **Step 2: Run test — fails**

- [ ] **Step 3: Implement ECDH-P256**

KEM encapsulate:
1. Generate ephemeral ECDH keypair
2. Compute shared secret via ECDH with recipient's public key
3. Derive symmetric key via HKDF
4. Return `{shared_secret, ephemeral_public_key_as_ciphertext}`

KEM decapsulate:
1. Receive ephemeral public key (ciphertext)
2. Compute shared secret via ECDH with own private key
3. Derive same symmetric key via HKDF
4. Return shared_secret

- [ ] **Step 4: Run test — passes**

- [ ] **Step 5: Commit**

```bash
git add src/pki_crypto/lib/pki_crypto/kem/ src/pki_crypto/test/pki_crypto/kem/
git commit -m "feat(pki_crypto): implement ECDH-P256 KEM algorithm"
```

---

### Task 6: Implement symmetric encryption and KDF utilities

**Files:**
- Create: `src/pki_crypto/lib/pki_crypto/symmetric.ex`
- Create: `src/pki_crypto/lib/pki_crypto/kdf.ex`
- Create: `src/pki_crypto/test/pki_crypto/symmetric_test.exs`
- Create: `src/pki_crypto/test/pki_crypto/kdf_test.exs`

- [ ] **Step 1: Write failing tests for Symmetric**

```elixir
# Tests:
# - encrypt then decrypt round-trip
# - decrypt with wrong key fails
# - different plaintexts produce different ciphertexts
# - empty plaintext works
# - large plaintext works (1MB)
```

- [ ] **Step 2: Write failing tests for KDF**

```elixir
# Tests:
# - derive_key returns 32-byte key
# - same input produces same output (deterministic)
# - different passwords produce different keys
# - different salts produce different keys
# - derive_session_key(password) convenience function
```

- [ ] **Step 3: Implement Symmetric (AES-256-GCM)**

```elixir
defmodule PkiCrypto.Symmetric do
  def encrypt(plaintext, key) when byte_size(key) == 32 do
    iv = :crypto.strong_rand_bytes(12)
    {ciphertext, tag} = :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, plaintext, "", true)
    {:ok, iv <> tag <> ciphertext}
  end

  def decrypt(<<iv::binary-12, tag::binary-16, ciphertext::binary>>, key) do
    case :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, ciphertext, "", tag, false) do
      plaintext when is_binary(plaintext) -> {:ok, plaintext}
      :error -> {:error, :decryption_failed}
    end
  end
end
```

- [ ] **Step 4: Implement KDF (HKDF-SHA-256)**

```elixir
defmodule PkiCrypto.Kdf do
  def derive_key(password, salt, opts \\ []) do
    length = Keyword.get(opts, :length, 32)
    info = Keyword.get(opts, :info, "pki_crypto")
    prk = :crypto.mac(:hmac, :sha256, salt, password)
    okm = hkdf_expand(prk, info, length)
    {:ok, okm}
  end

  def derive_session_key(password) do
    salt = :crypto.hash(:sha256, "pki_session_key_derivation")
    derive_key(password, salt, info: "session_key")
  end

  defp hkdf_expand(prk, info, length) do
    # HKDF-Expand per RFC 5869
    n = ceil(length / 32)
    {okm, _} =
      Enum.reduce(1..n, {<<>>, <<>>}, fn i, {acc, prev} ->
        t = :crypto.mac(:hmac, :sha256, prk, prev <> info <> <<i::8>>)
        {acc <> t, t}
      end)
    binary_part(okm, 0, length)
  end
end
```

- [ ] **Step 5: Run all tests — pass**

```bash
mix test test/pki_crypto/symmetric_test.exs test/pki_crypto/kdf_test.exs -v
```

- [ ] **Step 6: Commit**

```bash
git add src/pki_crypto/lib/pki_crypto/symmetric.ex src/pki_crypto/lib/pki_crypto/kdf.ex src/pki_crypto/test/pki_crypto/symmetric_test.exs src/pki_crypto/test/pki_crypto/kdf_test.exs
git commit -m "feat(pki_crypto): implement AES-256-GCM symmetric + HKDF key derivation"
```

---

### Task 7: Implement Shamir secret sharing

**Files:**
- Create: `src/pki_crypto/lib/pki_crypto/shamir.ex`
- Create: `src/pki_crypto/test/pki_crypto/shamir_test.exs`

- [ ] **Step 1: Write failing tests**

```elixir
# Tests:
# - split(secret, 2, 3) returns 3 shares
# - recover with any 2 of 3 shares returns original secret
# - recover with 1 of 3 shares fails (not enough)
# - split(secret, 3, 5) returns 5 shares, any 3 recover
# - split(secret, k, k) works (k equals n)
# - split with k < 2 fails
# - split with k > n fails
# - large secret (256 bytes) works
```

- [ ] **Step 2: Run tests — fail**

- [ ] **Step 3: Implement Shamir**

Delegates to `Keyx` library which implements Shamir's Secret Sharing:

```elixir
defmodule PkiCrypto.Shamir do
  @moduledoc "Shamir's Secret Sharing — split and recover secrets."

  def split(secret, k, n) when k >= 2 and k <= n and is_binary(secret) do
    shares = Keyx.Shamir.split(secret, k, n)
    {:ok, shares}
  rescue
    e -> {:error, Exception.message(e)}
  end

  def split(_secret, _k, _n), do: {:error, :invalid_threshold}

  def recover(shares) when is_list(shares) and length(shares) >= 1 do
    secret = Keyx.Shamir.recover(shares)
    {:ok, secret}
  rescue
    e -> {:error, Exception.message(e)}
  end
end
```

- [ ] **Step 4: Run tests — pass**

```bash
mix test test/pki_crypto/shamir_test.exs -v
```

- [ ] **Step 5: Commit**

```bash
git add src/pki_crypto/lib/pki_crypto/shamir.ex src/pki_crypto/test/pki_crypto/shamir_test.exs
git commit -m "feat(pki_crypto): implement Shamir secret sharing (split/recover)"
```

---

### Task 8: Implement Algorithm Registry

**Files:**
- Create: `src/pki_crypto/lib/pki_crypto/registry.ex`
- Create: `src/pki_crypto/test/pki_crypto/registry_test.exs`

- [ ] **Step 1: Write failing tests**

```elixir
# Tests:
# - get("RSA-4096") returns %PkiCrypto.Signing.RSA4096{}
# - get("ECC-P256") returns %PkiCrypto.Signing.ECCP256{}
# - get("ECDH-P256") returns %PkiCrypto.Kem.ECDHP256{}
# - get("unknown") returns nil
# - signing_algorithms returns only signing types
# - kem_algorithms returns only KEM types
# - all returns complete map
# - every registered algorithm passes generate_keypair
```

- [ ] **Step 2: Run tests — fail**

- [ ] **Step 3: Implement Registry**

```elixir
defmodule PkiCrypto.Registry do
  @moduledoc "Maps algorithm name strings to protocol-implementing structs."

  @algorithms %{
    "RSA-4096"   => %PkiCrypto.Signing.RSA4096{},
    "ECC-P256"   => %PkiCrypto.Signing.ECCP256{},
    "ECC-P384"   => %PkiCrypto.Signing.ECCP384{},
    "ECDH-P256"  => %PkiCrypto.Kem.ECDHP256{},
  }

  def get(name), do: Map.get(@algorithms, name)

  def signing_algorithms do
    @algorithms
    |> Enum.filter(fn {_, algo} -> PkiCrypto.Algorithm.algorithm_type(algo) == :signing end)
    |> Map.new()
  end

  def kem_algorithms do
    @algorithms
    |> Enum.filter(fn {_, algo} -> PkiCrypto.Algorithm.algorithm_type(algo) == :kem end)
    |> Map.new()
  end

  def all, do: @algorithms
end
```

- [ ] **Step 4: Run tests — pass**

```bash
mix test test/pki_crypto/registry_test.exs -v
```

- [ ] **Step 5: Run FULL test suite**

```bash
mix test -v
```

Expected: ALL tests pass across all modules

- [ ] **Step 6: Commit**

```bash
git add src/pki_crypto/lib/pki_crypto/registry.ex src/pki_crypto/test/pki_crypto/registry_test.exs
git commit -m "feat(pki_crypto): implement Algorithm Registry with name-to-struct lookup"
```

---

### Task 9: Wire pki_crypto into CA Engine (replace CryptoAdapter)

**Files:**
- Modify: `src/pki_ca_engine/mix.exs` — add `{:pki_crypto, path: "../pki_crypto"}`
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/key_ceremony/sync_ceremony.ex` — use `PkiCrypto.Algorithm` instead of `CryptoAdapter`
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/certificate_signing.ex` — use `PkiCrypto.Algorithm`
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/application.ex` — remove CryptoAdapter config
- Update: relevant tests

- [ ] **Step 1: Add dep to CA Engine mix.exs**

- [ ] **Step 2: Update SyncCeremony to use PkiCrypto.Algorithm**

Replace `CryptoAdapter.generate_keypair(adapter, algorithm)` with `PkiCrypto.Algorithm.generate_keypair(PkiCrypto.Registry.get(algorithm))`.

Replace `CryptoAdapter.split_secret(adapter, secret, k, n)` with `PkiCrypto.Shamir.split(secret, k, n)`.

Replace `CryptoAdapter.recover_secret(adapter, shares)` with `PkiCrypto.Shamir.recover(shares)`.

- [ ] **Step 3: Update CertificateSigning to use PkiCrypto.Algorithm**

- [ ] **Step 4: Update tests**

- [ ] **Step 5: Run CA Engine tests — all pass**

```bash
cd src/pki_ca_engine && mix test
```

- [ ] **Step 6: Commit**

```bash
git add src/pki_ca_engine/ src/pki_crypto/
git commit -m "refactor(ca_engine): replace CryptoAdapter with PkiCrypto.Algorithm protocol"
```

---

### Task 10: Wire pki_crypto into RA Engine and Validation

**Files:**
- Modify: `src/pki_ra_engine/mix.exs`
- Modify: `src/pki_validation/mix.exs`

- [ ] **Step 1: Add pki_crypto dep to RA Engine and Validation**

- [ ] **Step 2: Formalize CaClient behaviour**

```elixir
# src/pki_ra_engine/lib/pki_ra_engine/ca_client.ex
defmodule PkiRaEngine.CaClient do
  @callback sign_certificate(csr_pem :: String.t(), cert_profile :: map()) ::
              {:ok, map()} | {:error, term()}
end
```

Add `@behaviour PkiRaEngine.CaClient` and `@impl true` to DefaultCaClient and HttpCaClient.

- [ ] **Step 3: Run all tests across all services**

```bash
for dir in pki_crypto pki_ca_engine pki_ra_engine pki_validation; do
  echo "=== $dir ===" && (cd src/$dir && mix test)
done
```

Expected: ALL pass

- [ ] **Step 4: Commit**

```bash
git add src/
git commit -m "refactor: wire pki_crypto into all services, formalize CaClient behaviour"
```

- [ ] **Step 5: Push**

```bash
git push
```

---

## Plan Summary

| Task | What | Tests |
|------|------|-------|
| 1 | Mix project skeleton | Compiles |
| 2 | Protocol definition + shared test suite | Framework only |
| 3 | RSA-4096 signing | ~8 tests (shared + specific) |
| 4 | ECC-P256 + ECC-P384 signing | ~16 tests |
| 5 | ECDH-P256 KEM | ~10 tests |
| 6 | AES-256-GCM + HKDF | ~12 tests |
| 7 | Shamir secret sharing | ~8 tests |
| 8 | Algorithm Registry | ~8 tests |
| 9 | Wire into CA Engine | Existing tests pass |
| 10 | Wire into RA Engine + Validation | All tests pass |

**Total: ~60 new tests + all existing tests still passing**

Next plan (Plan 2: Platform + Multi-tenancy) will be written after this plan is implemented.
