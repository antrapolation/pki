# liboqs NIF for ML-DSA + SLH-DSA

**Date:** 2026-04-03
**Status:** Approved
**Goal:** Add NIST PQC digital signature support (ML-DSA FIPS 204, SLH-DSA FIPS 205) via C NIF wrapping liboqs, integrated into the PkiCrypto algorithm registry.

---

## 1. New OTP App: pki_oqs_nif

Standalone Elixir NIF library at `src/pki_oqs_nif/`.

```
src/pki_oqs_nif/
  mix.exs
  Makefile
  c_src/oqs_nif.c
  lib/pki_oqs_nif.ex
  priv/                    # compiled .so goes here
  test/pki_oqs_nif_test.exs
```

Links against liboqs installed at `/opt/homebrew/Cellar/liboqs/0.15.0` (macOS). For Linux, uses `pkg-config liboqs` or `/usr/local/lib`.

---

## 2. Algorithms

### ML-DSA (FIPS 204) — 3 variants

| Algorithm | liboqs Name | Security Level | Public Key | Signature |
|-----------|-------------|----------------|------------|-----------|
| ML-DSA-44 | `ML-DSA-44` | 2 (128-bit) | 1,312 B | 2,420 B |
| ML-DSA-65 | `ML-DSA-65` | 3 (192-bit) | 1,952 B | 3,293 B |
| ML-DSA-87 | `ML-DSA-87` | 5 (256-bit) | 2,592 B | 4,595 B |

### SLH-DSA SHA2 (FIPS 205) — 6 variants

| Algorithm | liboqs Name | Security | Sig Size | Speed |
|-----------|-------------|----------|----------|-------|
| SLH-DSA-SHA2-128f | `SLH-DSA-SHA2-128f` | 128-bit | 17,088 B | Fast |
| SLH-DSA-SHA2-128s | `SLH-DSA-SHA2-128s` | 128-bit | 7,856 B | Small |
| SLH-DSA-SHA2-192f | `SLH-DSA-SHA2-192f` | 192-bit | 35,664 B | Fast |
| SLH-DSA-SHA2-192s | `SLH-DSA-SHA2-192s` | 192-bit | 16,224 B | Small |
| SLH-DSA-SHA2-256f | `SLH-DSA-SHA2-256f` | 256-bit | 49,856 B | Fast |
| SLH-DSA-SHA2-256s | `SLH-DSA-SHA2-256s` | 256-bit | 29,792 B | Small |

**Total: 9 algorithms** (3 ML-DSA + 6 SLH-DSA SHA2).

---

## 3. C NIF Design

One C file (`c_src/oqs_nif.c`) with 3 NIF functions. The algorithm name is passed as a string argument — no per-algorithm C code needed.

```c
// NIF: oqs_keygen(algorithm_name_binary) → {:ok, %{public_key, private_key}} | {:error, reason}
static ERL_NIF_TERM nif_keygen(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

// NIF: oqs_sign(algorithm_name, private_key, message) → {:ok, signature} | {:error, reason}
static ERL_NIF_TERM nif_sign(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

// NIF: oqs_verify(algorithm_name, public_key, signature, message) → :ok | {:error, :invalid_signature}
static ERL_NIF_TERM nif_verify(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
```

**liboqs API usage:**
```c
OQS_SIG *sig = OQS_SIG_new("ML-DSA-65");
OQS_SIG_keypair(sig, public_key, secret_key);
OQS_SIG_sign(sig, signature, &sig_len, message, msg_len, secret_key);
OQS_SIG_verify(sig, message, msg_len, signature, sig_len, public_key);
OQS_SIG_free(sig);
```

**Memory safety:**
- All buffers allocated with `enif_alloc` / `enif_make_new_binary`
- `OQS_SIG_free` called in all paths (success and error)
- Secret key buffer zeroed before free (`OQS_MEM_secure_free`)

---

## 4. Elixir Wrapper

```elixir
defmodule PkiOqsNif do
  @on_load :load_nif

  def load_nif do
    nif_path = :filename.join(:code.priv_dir(:pki_oqs_nif), ~c"oqs_nif")
    :erlang.load_nif(nif_path, 0)
  end

  def keygen(algorithm), do: :erlang.nif_error(:nif_not_loaded)
  def sign(algorithm, private_key, message), do: :erlang.nif_error(:nif_not_loaded)
  def verify(algorithm, public_key, signature, message), do: :erlang.nif_error(:nif_not_loaded)
end
```

---

## 5. PkiCrypto Integration

### Algorithm structs (one per algorithm)

```elixir
# lib/pki_crypto/signing/ml_dsa.ex
defmodule PkiCrypto.Signing.MlDsa44 do
  defstruct []
end

defimpl PkiCrypto.Algorithm, for: PkiCrypto.Signing.MlDsa44 do
  def generate_keypair(_), do: PkiOqsNif.keygen("ML-DSA-44")
  def sign(_, private_key, data), do: PkiOqsNif.sign("ML-DSA-44", private_key, data)
  def verify(_, public_key, signature, data), do: PkiOqsNif.verify("ML-DSA-44", public_key, signature, data)
  def kem_encapsulate(_, _), do: {:error, :not_supported}
  def kem_decapsulate(_, _, _), do: {:error, :not_supported}
  def identifier(_), do: "ML-DSA-44"
  def algorithm_type(_), do: :signing
end
```

Same pattern for all 9 algorithms, changing only the struct name and liboqs algorithm string.

### Registry update

```elixir
@algorithms %{
  # Existing
  "RSA-4096"  => %PkiCrypto.Signing.RSA4096{},
  "ECC-P256"  => %PkiCrypto.Signing.ECCP256{},
  "ECC-P384"  => %PkiCrypto.Signing.ECCP384{},
  "ECDH-P256" => %PkiCrypto.Kem.ECDHP256{},
  # ML-DSA (FIPS 204)
  "ML-DSA-44" => %PkiCrypto.Signing.MlDsa44{},
  "ML-DSA-65" => %PkiCrypto.Signing.MlDsa65{},
  "ML-DSA-87" => %PkiCrypto.Signing.MlDsa87{},
  # SLH-DSA SHA2 (FIPS 205)
  "SLH-DSA-SHA2-128f" => %PkiCrypto.Signing.SlhDsaSha2128f{},
  "SLH-DSA-SHA2-128s" => %PkiCrypto.Signing.SlhDsaSha2128s{},
  "SLH-DSA-SHA2-192f" => %PkiCrypto.Signing.SlhDsaSha2192f{},
  "SLH-DSA-SHA2-192s" => %PkiCrypto.Signing.SlhDsaSha2192s{},
  "SLH-DSA-SHA2-256f" => %PkiCrypto.Signing.SlhDsaSha2256f{},
  "SLH-DSA-SHA2-256s" => %PkiCrypto.Signing.SlhDsaSha2256s{},
}
```

### Dependency chain

`pki_crypto` → `pki_oqs_nif` (path dep in mix.exs)

---

## 6. Build System (Makefile)

```makefile
LIBOQS_PREFIX ?= /opt/homebrew/Cellar/liboqs/0.15.0
CFLAGS = -O2 -Wall -I$(LIBOQS_PREFIX)/include -I$(ERTS_INCLUDE_DIR)
LDFLAGS = -L$(LIBOQS_PREFIX)/lib -loqs

priv/oqs_nif.so: c_src/oqs_nif.c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $< $(LDFLAGS)
```

Uses `ERTS_INCLUDE_DIR` from Erlang for `erl_nif.h`. On Linux, falls back to system liboqs paths.

---

## 7. Testing

Round-trip tests for each algorithm:

```elixir
test "ML-DSA-65 keygen → sign → verify" do
  {:ok, %{public_key: pk, private_key: sk}} = PkiOqsNif.keygen("ML-DSA-65")
  message = "test message"
  {:ok, sig} = PkiOqsNif.sign("ML-DSA-65", sk, message)
  assert :ok = PkiOqsNif.verify("ML-DSA-65", pk, sig, message)
end

test "ML-DSA-65 verify rejects wrong message" do
  {:ok, %{public_key: pk, private_key: sk}} = PkiOqsNif.keygen("ML-DSA-65")
  {:ok, sig} = PkiOqsNif.sign("ML-DSA-65", sk, "correct")
  assert {:error, :invalid_signature} = PkiOqsNif.verify("ML-DSA-65", pk, sig, "wrong")
end
```

---

## 8. What's NOT In Scope

- **SHAKE-based SLH-DSA variants** — add later by just adding registry entries (NIF already supports them)
- **ML-KEM (key encapsulation)** — future work, liboqs supports it
- **Certificate generation with PQC** — the existing ceremony/CSR flow uses X509 lib which doesn't support PQC OIDs; KAZ-SIGN uses ApJavaCrypto for this. ML-DSA/SLH-DSA cert generation is out of scope — keygen/sign/verify only.
- **Cross-platform build** — macOS first (Homebrew liboqs), Linux support via conditional Makefile paths
