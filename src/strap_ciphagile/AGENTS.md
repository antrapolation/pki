# AGENTS.md

## Project Overview

StrapCiphagile is an Elixir library implementing a custom binary serialization format for cryptographic objects (keys, hashes, signatures, KDFs, ciphers). It encodes/decodes structured cryptographic metadata to/from compact binary representations using a TSLV (Tag-Length Size-Length-Value) scheme.

The output from this project shall be the "Golden Reference" for the Cipher Agility format.

## Build & Test Commands

```bash
mix deps.get              # Fetch dependencies
mix compile               # Compile
mix test                  # Run all tests
mix test path/to/test.exs # Run a single test file
mix test --trace          # Run tests with timing output
mix format                # Format code
```

**Test setup note**: Tests require distributed Erlang when using the `ap_java_crypto` library. The test helper starts EPMD and creates a node `test@localhost`, then starts the `ap_java_crypto` applications. Both are local path dependencies (`../ap_java_crypto`) that must be present as sibling directories.

`ap_java_crypto` is to test for post-quantum cryptographic algorithms while the rest shall go to `ex_ccrypto`.

## Architecture

### Binary Format

All encoded data follows this structure:
```
[Magic: 0xAF 0x08] [Version: Context driven, 1 byte] [Header bytes] [VarLengthData fields...]
```

Variable-length data uses a 1–4 byte length prefix scheme (see `VarLengthData` module).

### Protocol-Driven Encode/Decode

Two Elixir protocols drive all serialization:
- `StrapCiphagile.EncoderProtocol` — each context struct implements `encode/2`
- `StrapCiphagile.DecoderProtocol` — each context struct implements `decode/2`

The main API (`StrapCiphagile.encode/2` and `StrapCiphagile.decode/1`) dispatches to the correct protocol implementation based on struct type (encode) or binary tag byte (decode).

### Context Modules (`lib/strap_ciphagile/context/`)

Each context is a `TypedStruct` with its own encoder/decoder implementation:

| Module | Tag | Purpose |
|---|---|---|
| `Hashing` | 0x01 | Hash algorithm metadata (SHA-2/3, PHOTON, SPONGENT, etc.) |
| `KDF` | 0x02 | Key derivation configs (Argon2, PBKDF2, BCrypt, Scrypt) with nested config structs |
| `Symkey` | 0x10 | Symmetric keys (AES, ChaCha20, Camellia, etc.) with optional KDF |
| `SymkeyCipher` | 0x0A | Symmetric encryption with mode (CBC, GCM, XTS) — wraps a Symkey |
| `Signature` | 0x08 | Digital signatures (RSA, ECC, ML-DSA, Falcon, SLH-DSA) with optional Hashing digest |
| `PublicKey` | 0x11 | Public key storage with format metadata |
| `PrivateKey` | 0x12 | Private key storage, optionally encrypted |

Context modules nest: `SymkeyCipher` contains a `Symkey`, `Symkey` can contain a `KDF`, `Signature` can contain a `Hashing`.

### Key Supporting Modules

- **`Tags`** — binary tag constants and `tag_value/1` for atom-to-byte mapping
- **`VarLengthData`** — variable-length binary encoding/decoding
- **`Asymkey.Encodings`** — extensive algorithm/variant/curve atom-to-byte mappings (140+ ECC curves, post-quantum variants)

## Conventions

- All public functions return `{:ok, value}` or `{:error, reason}` tuples
- `with` chains for error propagation through encode/decode pipelines
- Binary pattern matching with explicit size specs: `<<tag, rest::binary>>`, `<<len::8, data::binary-size(len), rest::binary>>`
- Optional fields (salt, digest, iv) encode as empty binaries when nil and are skipped during TLV construction
- Algorithm/variant atoms map to single bytes (e.g., `:aes` → `0x01`, `:sha2_256` → `0x01`)
- Test pattern: round-trip encode → decode → assert structural equality
