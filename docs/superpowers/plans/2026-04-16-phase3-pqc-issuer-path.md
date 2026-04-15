# Phase 3 — PQC Issuer Path + JSON Wrapper Retirement — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the cross-algorithm signing matrix by enabling PQC issuers (ML-DSA, KAZ-SIGN) to sign any subject in real X.509 format. Retire the JSON-wrapper pseudo-certificate format. Unify ceremony CSR/self-sign emission through the Phase 2 primitives so the CA-portal "Generate CSR → sign by parent" UI flow works end-to-end for PQC sub-CAs.

**Architecture:** Extend `PkiCrypto.X509Builder.sign_tbs/3` with a PQC-issuer branch that calls `PkiCrypto.Algorithm.sign/3`. Add `PkiCrypto.X509Builder.self_sign/4` for root CAs (where issuer = subject). Collapse the algorithm-family branching in `PkiCaEngine.CertificateSigning.do_sign/6` and `CeremonyOrchestrator.generate_csr/4` + `generate_self_signed/4` into single unified calls. Delete `do_sign_kaz`, `do_sign_ml_dsa`, `generate_pqc_csr`, `generate_pqc_self_signed`, `KazSign.self_sign` call sites, and all their JSON-wrapper helpers. Pass issuer algorithm_id from the `issuer_key_record.algorithm` column rather than inferring from the cert's public-key structure.

**Tech Stack:** Elixir 1.18, Erlang/OTP 25, `:public_key`, `pki_crypto` (Phase 1+2 modules).

---

## Prerequisites (from Phases 1 + 2)

- `PkiCrypto.AlgorithmRegistry.by_id/1` / `by_oid/1`.
- `PkiCrypto.Csr.parse/1`, `generate/3`, `verify_pop/1`.
- `PkiCrypto.X509Builder.build_tbs_cert/5`, `sign_tbs/3` (classical issuer only; PQC returns `{:error, :pqc_issuer_not_yet_supported}`).
- `PkiCaEngine.CertificateSigning.sign_with_issuer/6` already routes through the new orchestrator for classical issuers.
- RSA-2048 signer added to `pki_crypto` Registry during Phase 2.

## File structure

**Created:**
- `src/pki_crypto/test/pki_crypto/integration/pqc_issuer_test.exs` — new cross-algo matrix tests.

**Modified:**
- `src/pki_crypto/lib/pki_crypto/x509_builder.ex` — add PQC issuer branch to `sign_tbs/3`; add `self_sign/4`.
- `src/pki_crypto/test/pki_crypto/x509_builder_test.exs` — tests for PQC issuer + self-sign.
- `src/pki_ca_engine/lib/pki_ca_engine/certificate_signing.ex` — collapse PQC issuer branches into the unified orchestrator path; pass `issuer_key_record.algorithm` directly; delete JSON wrapper helpers.
- `src/pki_ca_engine/lib/pki_ca_engine/ceremony_orchestrator.ex` — route `generate_csr/4` and `generate_self_signed/4` through `PkiCrypto.Csr` + `X509Builder`; delete PQC-specific helpers.
- `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/direct.ex` — replace residual `KazSign.generate_csr` calls with `PkiCrypto.Csr.generate`.

**Out of scope for Phase 3:**
- OCSP/CRL PQC signing (Phase 4).
- Hybrid / composite signatures (deferred indefinitely).

---

## Shared reference

### Cross-algorithm matrix completeness

| issuer family | subject family | current state after Phase 2 | Phase 3 fixes |
|---|---|---|---|
| classical | classical | works | no change |
| classical | PQC | works | no change |
| PQC | classical | `:pqc_issuer_not_yet_supported` | Task 1 adds PQC branch |
| PQC | PQC (same family) | JSON wrapper via `do_sign_kaz` | Task 2 removes JSON, routes through new path |
| PQC | PQC (cross family) | no path | Task 2 route works for this implicitly |

### Algorithm id source of truth

The `issuer_keys` table stores `algorithm` as a string (e.g. `"ECC-P384"`, `"KAZ-SIGN-192"`). This column is the authoritative issuer algorithm — not the cert's SPKI. `CertificateSigning.do_sign/6` has `issuer_key_record.algorithm` in scope. Passing this directly to `X509Builder.sign_tbs/3` is simpler and removes the `X509.Certificate.public_key(issuer_cert)` dispatch introduced in Phase 2.

---

## Task 1: `X509Builder.sign_tbs/3` — PQC issuer branch

**Files:**
- Modify: `src/pki_crypto/lib/pki_crypto/x509_builder.ex`
- Modify: `src/pki_crypto/test/pki_crypto/x509_builder_test.exs`

- [ ] **Step 1: Write failing test**

Append to `src/pki_crypto/test/pki_crypto/x509_builder_test.exs`:

```elixir
  describe "sign_tbs/3 — PQC issuer" do
    setup do
      # PQC issuer: KAZ-SIGN-192 root
      algo = PkiCrypto.Registry.get("KAZ-SIGN-192")
      {:ok, %{public_key: root_pub, private_key: root_priv}} = PkiCrypto.Algorithm.generate_keypair(algo)

      # Classical subject: ECDSA-P256 sub-CA
      sub_priv = X509.PrivateKey.new_ec(:secp256r1)
      {:ok, csr_pem} = PkiCrypto.Csr.generate("ECC-P256", sub_priv, "/CN=ECDSA Sub")
      {:ok, csr} = PkiCrypto.Csr.parse(csr_pem)

      # We need a root cert for the AKI extension. For PQC roots the "issuer cert"
      # would have been built by X509Builder.self_sign/4 (Task 3). For this test
      # we use a stub self-signed X.509 with PQC SPKI — constructed directly.
      version = PkiCrypto.Asn1.tagged(0, :explicit, PkiCrypto.Asn1.integer(2))
      serial = PkiCrypto.Asn1.integer(1)
      {:ok, %{sig_alg_oid: oid, public_key_oid: pk_oid}} = PkiCrypto.AlgorithmRegistry.by_id("KAZ-SIGN-192")
      sig_alg = PkiCrypto.Asn1.sequence([PkiCrypto.Asn1.oid(oid)])
      name = encode_test_name("/CN=KAZ Root")
      now = DateTime.utc_now() |> DateTime.truncate(:second)
      not_after = DateTime.add(now, 365 * 86400, :second)
      validity = PkiCrypto.Asn1.sequence([PkiCrypto.Asn1.utc_time(now), PkiCrypto.Asn1.utc_time(not_after)])
      spki = PkiCrypto.Asn1.sequence([
        PkiCrypto.Asn1.sequence([PkiCrypto.Asn1.oid(pk_oid)]),
        PkiCrypto.Asn1.bit_string(root_pub)
      ])
      tbs_root = PkiCrypto.Asn1.sequence([version, serial, sig_alg, name, validity, name, spki])
      {:ok, sig} = PkiCrypto.Algorithm.sign(algo, root_priv, tbs_root)
      root_cert_der = PkiCrypto.Asn1.sequence([tbs_root, sig_alg, PkiCrypto.Asn1.bit_string(sig)])

      %{algo: algo, root_priv: root_priv, root_pub: root_pub, root_cert_der: root_cert_der, csr: csr}
    end

    test "KAZ-SIGN-192 root signs ECDSA sub-CA CSR; signature verifies", ctx do
      {:ok, tbs, _} =
        PkiCrypto.X509Builder.build_tbs_cert(
          ctx.csr,
          %{cert_der: ctx.root_cert_der, algorithm_id: "KAZ-SIGN-192"},
          "/CN=ECDSA Sub",
          365,
          5001
        )

      {:ok, cert_der} = PkiCrypto.X509Builder.sign_tbs(tbs, "KAZ-SIGN-192", ctx.root_priv)

      # Parse back
      {outer, <<>>} = PkiCrypto.Asn1.read_sequence(cert_der)
      [tbs_back, sig_alg, sig_bits] = PkiCrypto.Asn1.read_sequence_items(outer)
      assert tbs_back == tbs

      {alg_body, <<>>} = PkiCrypto.Asn1.read_sequence(sig_alg)
      [alg_oid_der] = PkiCrypto.Asn1.read_sequence_items(alg_body)
      {oid, <<>>} = PkiCrypto.Asn1.read_oid(alg_oid_der)
      assert oid == {1, 3, 6, 1, 4, 1, 99999, 1, 1, 2}  # KAZ-SIGN-192 placeholder OID

      {signature, <<>>} = PkiCrypto.Asn1.read_bit_string(sig_bits)
      assert :ok = PkiCrypto.Algorithm.verify(ctx.algo, ctx.root_pub, signature, tbs)
    end

    test "ML-DSA-65 root signs KAZ-SIGN-128 leaf (cross-family PQC)" do
      ml_dsa = PkiCrypto.Registry.get("ML-DSA-65")
      kaz = PkiCrypto.Registry.get("KAZ-SIGN-128")

      {:ok, %{public_key: root_pub, private_key: root_priv}} =
        PkiCrypto.Algorithm.generate_keypair(ml_dsa)

      {:ok, %{public_key: leaf_pub, private_key: leaf_priv}} =
        PkiCrypto.Algorithm.generate_keypair(kaz)

      {:ok, csr_pem} =
        PkiCrypto.Csr.generate("KAZ-SIGN-128", %{public_key: leaf_pub, private_key: leaf_priv}, "/CN=KAZ Leaf")

      {:ok, csr} = PkiCrypto.Csr.parse(csr_pem)
      assert :ok = PkiCrypto.Csr.verify_pop(csr)

      # Minimal ML-DSA root cert DER for AKI
      {:ok, root_cert_der} =
        PkiCrypto.X509Builder.self_sign("ML-DSA-65", %{public_key: root_pub, private_key: root_priv}, "/CN=ML-DSA Root", 3650)

      {:ok, tbs, _} =
        PkiCrypto.X509Builder.build_tbs_cert(
          csr,
          %{cert_der: root_cert_der, algorithm_id: "ML-DSA-65"},
          "/CN=KAZ Leaf",
          365,
          6001
        )

      {:ok, cert_der} = PkiCrypto.X509Builder.sign_tbs(tbs, "ML-DSA-65", root_priv)

      {outer, <<>>} = PkiCrypto.Asn1.read_sequence(cert_der)
      [_tbs_back, _sig_alg, sig_bits] = PkiCrypto.Asn1.read_sequence_items(outer)
      {signature, <<>>} = PkiCrypto.Asn1.read_bit_string(sig_bits)

      assert :ok = PkiCrypto.Algorithm.verify(ml_dsa, root_pub, signature, tbs)
    end
  end

  # Helper reused by the PQC issuer tests above (uses Asn1 primitives only).
  defp encode_test_name(dn_string) do
    parts =
      dn_string
      |> String.split("/", trim: true)
      |> Enum.map(fn part ->
        [k, v] = String.split(part, "=", parts: 2)
        {dn_key_to_oid(k), v}
      end)

    rdns =
      Enum.map(parts, fn {oid, value} ->
        atv = PkiCrypto.Asn1.sequence([
          PkiCrypto.Asn1.oid(oid),
          <<0x0C, byte_size(value)>> <> value
        ])
        PkiCrypto.Asn1.set([atv])
      end)

    PkiCrypto.Asn1.sequence(rdns)
  end

  defp dn_key_to_oid("CN"), do: {2, 5, 4, 3}
```

The second test depends on `X509Builder.self_sign/4` which Task 3 adds. If `self_sign/4` is not yet defined, the test will fail at compile; that's fine — do Task 3 before running this test green.

- [ ] **Step 2: Run to verify fails**

```
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_crypto && mix test test/pki_crypto/x509_builder_test.exs
```

Expected: new tests fail (first: `:pqc_issuer_not_yet_supported`; second: `self_sign/4` undefined).

- [ ] **Step 3: Add PQC issuer branch in `sign_tbs/3`**

In `src/pki_crypto/lib/pki_crypto/x509_builder.ex`, locate `sign_tbs/3` and replace the PQC branch. The full function becomes:

```elixir
  def sign_tbs(tbs_der, issuer_algorithm_id, issuer_private_key) do
    case AlgorithmRegistry.by_id(issuer_algorithm_id) do
      {:ok, %{family: :ecdsa} = meta} ->
        hash = ecdsa_hash_for(issuer_algorithm_id)
        signature = :public_key.sign(tbs_der, hash, issuer_private_key)
        {:ok, wrap_cert(tbs_der, meta.sig_alg_oid, signature)}

      {:ok, %{family: :rsa} = meta} ->
        signature = :public_key.sign(tbs_der, :sha256, issuer_private_key)
        {:ok, wrap_cert(tbs_der, meta.sig_alg_oid, signature)}

      {:ok, %{family: family} = meta} when family in [:ml_dsa, :kaz_sign, :slh_dsa] ->
        algo = PkiCrypto.Registry.get(issuer_algorithm_id)

        case PkiCrypto.Algorithm.sign(algo, issuer_private_key, tbs_der) do
          {:ok, signature} -> {:ok, wrap_cert(tbs_der, meta.sig_alg_oid, signature)}
          other -> {:error, {:pqc_sign_failed, other}}
        end

      :error ->
        {:error, :unknown_issuer_algorithm}
    end
  end
```

- [ ] **Step 4: Run just the first new test** (skip the self-sign one until Task 3):

```
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_crypto && mix test test/pki_crypto/x509_builder_test.exs --only describe:"sign_tbs/3 — PQC issuer" test/pki_crypto/x509_builder_test.exs:<line_of_first_pqc_test>
```

Or simpler — run the whole file; expect 1 new test pass, 1 still failing (self_sign).

- [ ] **Step 5: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki
git add src/pki_crypto/lib/pki_crypto/x509_builder.ex src/pki_crypto/test/pki_crypto/x509_builder_test.exs
git commit -m "feat(pki_crypto): X509Builder.sign_tbs PQC issuer branch"
```

---

## Task 2: Unified `do_sign` — route every issuer through the orchestrator; delete JSON helpers

**Files:**
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/certificate_signing.ex`

Currently `do_sign/6` branches on `normalize_algo(algorithm)` into `do_sign_kaz`, `do_sign_ml_dsa`, or `sign_with_issuer`. After Phase 2, `sign_with_issuer` handles classical issuers via the orchestrator. Phase 3 collapses the branches: **every issuer goes through `sign_with_issuer`**, which now uses `issuer_key_record.algorithm` (the authoritative algorithm id) instead of inferring from the issuer cert's public key.

- [ ] **Step 1: Read the current shape**

```
sed -n '170,220p' src/pki_ca_engine/lib/pki_ca_engine/certificate_signing.ex
```

Note how `do_sign/6` dispatches and that `sign_with_issuer/6` currently accepts a decoded `issuer_key` (a `:public_key` record for classical). For PQC issuers we need raw private-key bytes instead.

- [ ] **Step 2: Rewrite `do_sign/6` to always go through the orchestrator**

Replace `do_sign/6` with:

```elixir
  defp do_sign(issuer_key_record, private_key_der, csr_pem, subject_dn, validity_days, serial) do
    issuer_alg_id = issuer_key_record.algorithm
    issuer_cert_der = issuer_key_record.certificate_der
    serial_int = hex_serial_to_integer(serial)

    if issuer_cert_der == nil do
      Logger.error("Cannot sign: issuer key #{issuer_key_record.id} has no certificate")
      {:error, :issuer_certificate_not_available}
    else
      issuer_key = decode_issuer_key(issuer_alg_id, private_key_der)

      with {:ok, csr} <- PkiCrypto.Csr.parse(csr_pem),
           :ok <- PkiCrypto.Csr.verify_pop(csr),
           {:ok, tbs, _} <-
             PkiCrypto.X509Builder.build_tbs_cert(
               csr,
               %{cert_der: issuer_cert_der, algorithm_id: issuer_alg_id},
               subject_dn,
               validity_days,
               serial_int
             ),
           {:ok, cert_der} <- PkiCrypto.X509Builder.sign_tbs(tbs, issuer_alg_id, issuer_key) do
        cert_pem = :public_key.pem_encode([{:Certificate, cert_der, :not_encrypted}])
        {:ok, cert_der, cert_pem}
      else
        {:error, reason} ->
          Logger.error("Certificate signing failed: #{inspect(reason)}")
          {:error, {:signing_failed, reason}}
      end
    end
  end

  # Decode the at-rest private key into the form the signer expects.
  # Classical: :public_key record. PQC: raw bytes (pass-through).
  defp decode_issuer_key(algorithm_id, der) when algorithm_id in ["ECC-P256", "ECC-P384"] do
    :public_key.der_decode(:ECPrivateKey, der)
  end

  defp decode_issuer_key(algorithm_id, der) when algorithm_id in ["RSA-2048", "RSA-4096"] do
    :public_key.der_decode(:RSAPrivateKey, der)
  end

  defp decode_issuer_key(algorithm_id, bytes) do
    case PkiCrypto.AlgorithmRegistry.by_id(algorithm_id) do
      {:ok, %{family: family}} when family in [:ml_dsa, :kaz_sign, :slh_dsa] -> bytes
      _ -> raise "unknown issuer algorithm: #{algorithm_id}"
    end
  end
```

- [ ] **Step 3: Delete now-unused helpers**

Remove these functions from `certificate_signing.ex` (they are no longer reachable):
- `normalize_algo/1` (if only `do_sign` used it — verify via `grep normalize_algo`).
- `do_sign_kaz/7`
- `do_sign_ml_dsa/7`
- `kaz_level/1`
- `ml_dsa_oqs_name/1`
- `extract_public_key_bytes_from_csr/1` (both arities)
- `issuer_dn_string/1` (if only `do_sign_kaz`/`do_sign_ml_dsa` used it)
- `sign_with_issuer/6` (Phase 2's classical-only wrapper — now inlined above)
- `do_sign_with_issuer/5` (if any remains — Phase 2 should have deleted it already)
- `issuer_algorithm_id/1` from Phase 2 (no longer needed since we pass from the record)

Run a grep for each name before deleting to confirm it has no other callers in the file. If a function has external callers outside `certificate_signing.ex`, DO NOT delete it — report BLOCKED.

- [ ] **Step 4: Run tests**

```
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_engine && mix test 2>&1 | tail -10
```

Expected: 482 tests continue to pass. Any regression points to a caller still expecting JSON-wrapped cert output. Report BLOCKED if a test fails with a message mentioning JSON or `"-----BEGIN PKI CERTIFICATE-----"`.

- [ ] **Step 5: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki
git add src/pki_ca_engine/lib/pki_ca_engine/certificate_signing.ex
git commit -m "refactor(pki_ca_engine): route PQC issuer through unified orchestrator; delete JSON helpers"
```

---

## Task 3: `X509Builder.self_sign/4` — root CA self-signed cert

**Files:**
- Modify: `src/pki_crypto/lib/pki_crypto/x509_builder.ex`
- Modify: `src/pki_crypto/test/pki_crypto/x509_builder_test.exs`

A root CA self-issues its first cert where issuer = subject and the cert is signed with its own private key. Currently ceremonies emit this via `X509.Certificate.self_signed` (classical) or `KazSign.self_sign` (JSON wrapper for PQC). We add one unified entry point.

- [ ] **Step 1: Write failing tests**

Append to `src/pki_crypto/test/pki_crypto/x509_builder_test.exs`:

```elixir
  describe "self_sign/4" do
    test "classical ECDSA-P384 self-signed cert" do
      priv = X509.PrivateKey.new_ec(:secp384r1)
      pub = X509.PublicKey.derive(priv)

      {:ok, cert_der} =
        PkiCrypto.X509Builder.self_sign(
          "ECC-P384",
          %{public_key: pub, private_key: priv},
          "/CN=Classical Root",
          3650
        )

      assert <<0x30, _::binary>> = cert_der

      {outer, <<>>} = PkiCrypto.Asn1.read_sequence(cert_der)
      [tbs, _sig_alg, sig_bits] = PkiCrypto.Asn1.read_sequence_items(outer)
      {signature, <<>>} = PkiCrypto.Asn1.read_bit_string(sig_bits)

      assert :public_key.verify(tbs, :sha384, signature, pub)
    end

    test "PQC KAZ-SIGN-192 self-signed cert" do
      algo = PkiCrypto.Registry.get("KAZ-SIGN-192")
      {:ok, %{public_key: pub, private_key: priv}} = PkiCrypto.Algorithm.generate_keypair(algo)

      {:ok, cert_der} =
        PkiCrypto.X509Builder.self_sign(
          "KAZ-SIGN-192",
          %{public_key: pub, private_key: priv},
          "/CN=KAZ Root",
          3650
        )

      {outer, <<>>} = PkiCrypto.Asn1.read_sequence(cert_der)
      [tbs, _sig_alg, sig_bits] = PkiCrypto.Asn1.read_sequence_items(outer)
      {signature, <<>>} = PkiCrypto.Asn1.read_bit_string(sig_bits)

      assert :ok = PkiCrypto.Algorithm.verify(algo, pub, signature, tbs)
      assert :binary.match(cert_der, pub) != :nomatch
    end
  end
```

- [ ] **Step 2: Run to verify fails**

Expected: `self_sign/4` undefined.

- [ ] **Step 3: Add `self_sign/4`**

In `src/pki_crypto/lib/pki_crypto/x509_builder.ex`, add:

```elixir
  @doc """
  Build and sign a self-signed X.509 root certificate.

  `key` must be `%{public_key: binary, private_key: term}` — for classical
  algorithms the `private_key` is the `:public_key` record; for PQC it's the
  raw NIF bytes. `subject_dn` is a slash-separated DN string. `validity_days`
  applies to both notBefore (now) and notAfter (now + days).

  Returns `{:ok, cert_der}`.
  """
  @spec self_sign(String.t(), map(), String.t(), pos_integer()) ::
          {:ok, binary()} | {:error, term()}
  def self_sign(algorithm_id, %{public_key: pub, private_key: priv}, subject_dn, validity_days) do
    with {:ok, %{public_key_oid: pk_oid, sig_alg_oid: sig_oid}} <-
           AlgorithmRegistry.by_id(algorithm_id) do
      version = Asn1.tagged(0, :explicit, Asn1.integer(2))
      serial = Asn1.integer(:crypto.strong_rand_bytes(8) |> :binary.decode_unsigned())
      sig_alg = Asn1.sequence([Asn1.oid(sig_oid)])
      name = encode_name_from_dn_string(subject_dn)

      now = DateTime.utc_now() |> DateTime.truncate(:second)
      not_after = DateTime.add(now, validity_days * 86_400, :second)
      validity = Asn1.sequence([encode_time(now), encode_time(not_after)])

      spki_pub_bytes = classical_pub_to_raw_or_pqc(algorithm_id, pub)

      spki =
        Asn1.sequence([
          Asn1.sequence([Asn1.oid(pk_oid)]),
          Asn1.bit_string(spki_pub_bytes)
        ])

      # Root CA extensions: CA:TRUE, keyCertSign | cRLSign, SKI only (AKI omitted for self-signed).
      bc = root_bc_extension()
      ku = root_ku_extension()
      ski = make_extension({2, 5, 29, 14}, false, Asn1.octet_string(sha1(spki_pub_bytes)))
      ext_seq = Asn1.sequence([bc, ku, ski])
      extensions = Asn1.tagged(3, :explicit, ext_seq)

      tbs =
        Asn1.sequence([
          version,
          serial,
          sig_alg,
          name,
          validity,
          name,
          spki,
          extensions
        ])

      sign_tbs(tbs, algorithm_id, priv)
    end
  end

  # Extract the raw public-key bytes suitable for the SubjectPublicKeyInfo
  # bit-string content. PQC algorithms store this directly; classical requires
  # the key in its ASN.1 subjectPublicKey form.
  defp classical_pub_to_raw_or_pqc(algorithm_id, pub) do
    case AlgorithmRegistry.by_id(algorithm_id) do
      {:ok, %{family: family}} when family in [:ml_dsa, :kaz_sign, :slh_dsa] ->
        # PQC: `pub` is already raw bytes.
        pub

      {:ok, %{family: :ecdsa}} ->
        # Classical ECDSA: `pub` is `{{:ECPoint, point}, _params}` — extract point.
        case pub do
          {{:ECPoint, point}, _params} -> point
          %{} = _ -> raise "unexpected ECDSA public key shape: #{inspect(pub)}"
        end

      {:ok, %{family: :rsa}} ->
        :public_key.der_encode(:RSAPublicKey, pub)
    end
  end

  defp root_bc_extension do
    make_extension({2, 5, 29, 19}, true, Asn1.sequence([Asn1.boolean(true)]))
  end

  defp root_ku_extension do
    make_extension({2, 5, 29, 15}, true, key_usage_keycertsign_crlsign())
  end
```

If the classical ECDSA SPKI assertion fails on verify (likely because real X.509 SPKI for ECDSA includes curve parameters in the AlgorithmIdentifier — `namedCurve`), update the SPKI construction for ECDSA to include `curve` params:

```elixir
      # For ECDSA, the AlgorithmIdentifier must carry the named-curve OID as
      # algorithm parameters; otherwise :public_key.verify can't reconstruct
      # the public point.
      alg_id_der =
        if algorithm_id == "ECC-P256" do
          Asn1.sequence([Asn1.oid(pk_oid), Asn1.oid({1, 2, 840, 10045, 3, 1, 7})])
        else
          Asn1.sequence([Asn1.oid(pk_oid), Asn1.oid({1, 3, 132, 0, 34})])
        end
```

and use `alg_id_der` in the SPKI instead of the bare `Asn1.sequence([Asn1.oid(pk_oid)])`. PQC algorithms omit parameters.

- [ ] **Step 4: Run tests**

```
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_crypto && mix test test/pki_crypto/x509_builder_test.exs
```

Expected: all tests pass. The PQC self-sign test and the Task 1 PQC issuer tests should now be green together.

- [ ] **Step 5: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki
git add src/pki_crypto/lib/pki_crypto/x509_builder.ex src/pki_crypto/test/pki_crypto/x509_builder_test.exs
git commit -m "feat(pki_crypto): X509Builder.self_sign/4 for classical + PQC root CAs"
```

---

## Task 4: Unify `CeremonyOrchestrator.generate_csr/4` through `PkiCrypto.Csr.generate`

**Files:**
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/ceremony_orchestrator.ex`

`CeremonyOrchestrator.generate_csr/4` at line 472 currently branches on `classify_algorithm/1` and calls `KazSign.generate_csr` (JSON wrapper) or `generate_pqc_csr` (ML-DSA JSON). Replace with one call to `PkiCrypto.Csr.generate/3`.

- [ ] **Step 1: Read current state**

```
sed -n '440,540p' src/pki_ca_engine/lib/pki_ca_engine/ceremony_orchestrator.ex
```

Note the existing helpers: `classify_algorithm/1`, `generate_pqc_csr/4`, `decode_private_key/1`, `pem_encode/2`.

- [ ] **Step 2: Replace `generate_csr/4` body**

Replace the function with:

```elixir
  defp generate_csr(algorithm, private_key, public_key, subject_dn) do
    case PkiCrypto.AlgorithmRegistry.by_id(algorithm) do
      {:ok, %{family: family}} when family in [:ml_dsa, :kaz_sign, :slh_dsa] ->
        PkiCrypto.Csr.generate(algorithm, %{public_key: public_key, private_key: private_key}, subject_dn)

      {:ok, %{family: _classical}} ->
        try do
          native_key = decode_private_key(private_key)
          {:ok, PkiCrypto.Csr.generate(algorithm, native_key, subject_dn) |> elem(1)}
        rescue
          e -> {:error, e}
        end

      :error ->
        {:error, {:unknown_algorithm, algorithm}}
    end
  end
```

(The classical branch reuses the existing `decode_private_key/1` helper which takes raw DER and returns a `:public_key` record.)

- [ ] **Step 3: Delete `generate_pqc_csr/4`** (lines ~529–551) — it's unreachable.

Do NOT delete `classify_algorithm/1` yet — it's used by `generate_self_signed/4` (Task 5).

- [ ] **Step 4: Run tests**

```
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_engine && mix test test/pki_ca_engine/ceremony_orchestrator_test.exs 2>&1 | tail -10
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_engine && mix test 2>&1 | tail -5
```

Expected: all tests pass. If tests reference the old JSON PEM header (`"CERTIFICATE REQUEST"` vs `"-----BEGIN CERTIFICATE REQUEST-----"`), investigate; `PkiCrypto.Csr.generate` emits the standard PEM header so format-checking assertions should still pass.

- [ ] **Step 5: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki
git add src/pki_ca_engine/lib/pki_ca_engine/ceremony_orchestrator.ex
git commit -m "refactor(pki_ca_engine): ceremony generate_csr uses unified PkiCrypto.Csr.generate"
```

---

## Task 5: Unify `CeremonyOrchestrator.generate_self_signed/4` through `X509Builder.self_sign`

**Files:**
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/ceremony_orchestrator.ex`

`generate_self_signed/4` at line 445 still calls `KazSign.self_sign` (JSON wrapper) and `generate_pqc_self_signed` (ML-DSA JSON). Replace with `PkiCrypto.X509Builder.self_sign/4`.

- [ ] **Step 1: Replace `generate_self_signed/4`**

```elixir
  defp generate_self_signed(algorithm, private_key, public_key, subject_dn) do
    case PkiCrypto.AlgorithmRegistry.by_id(algorithm) do
      {:ok, %{family: family}} when family in [:ml_dsa, :kaz_sign, :slh_dsa] ->
        case PkiCrypto.X509Builder.self_sign(
               algorithm,
               %{public_key: public_key, private_key: private_key},
               subject_dn,
               365 * 25
             ) do
          {:ok, cert_der} ->
            cert_pem = :public_key.pem_encode([{:Certificate, cert_der, :not_encrypted}])
            {:ok, cert_der, cert_pem}

          error ->
            error
        end

      {:ok, %{family: _classical}} ->
        try do
          native_key = decode_private_key(private_key)

          root_cert =
            X509.Certificate.self_signed(
              native_key,
              subject_dn,
              template: :root_ca,
              hash: :sha256,
              serial: {:random, 8},
              validity: 365 * 25
            )

          cert_der = X509.Certificate.to_der(root_cert)
          cert_pem = X509.Certificate.to_pem(root_cert)
          {:ok, cert_der, cert_pem}
        rescue
          e -> {:error, e}
        end

      :error ->
        {:error, {:unknown_algorithm, algorithm}}
    end
  end
```

- [ ] **Step 2: Delete `generate_pqc_self_signed/4`** (lines ~495–527) and `classify_algorithm/1` (line ~553) if neither has remaining callers. Check with grep:

```
grep -n "classify_algorithm\|generate_pqc_self_signed" src/pki_ca_engine/lib/pki_ca_engine/ceremony_orchestrator.ex
```

Remove whatever is now orphaned.

- [ ] **Step 3: Run tests**

```
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_engine && mix test 2>&1 | tail -10
```

Expected: all tests pass. If a test exercises a KAZ-SIGN root ceremony that previously produced a JSON cert and now produces X.509, the test assertion on the PEM header or the cert format may need updating — but that's a legitimate test fix, not a regression.

- [ ] **Step 4: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki
git add src/pki_ca_engine/lib/pki_ca_engine/ceremony_orchestrator.ex
git commit -m "refactor(pki_ca_engine): ceremony generate_self_signed uses X509Builder.self_sign"
```

---

## Task 6: Clean `pki_ca_portal/direct.ex` residual `KazSign.generate_csr` calls

**Files:**
- Modify: `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/direct.ex`

Two call sites: line ~499 and line ~1482 (per grep). Both build PQC CSRs via the legacy API.

- [ ] **Step 1: Read each call site to understand the surrounding flow**

```
sed -n '485,515p' src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/direct.ex
sed -n '1470,1495p' src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/direct.ex
```

Note what each flow does with the returned DER. Make sure the replacement emits DER (not PEM) if the caller expects DER, or PEM if PEM.

- [ ] **Step 2: Replace each call**

Replace the `with :ok <- KazSign.init(level), {:ok, csr_der} <- KazSign.generate_csr(level, private_key, public_key, subject_dn) do` pattern with:

```elixir
        case PkiCrypto.Csr.generate(algorithm, %{public_key: public_key, private_key: private_key}, subject_dn) do
          {:ok, csr_pem} ->
            csr_der = pem_to_der(csr_pem)
            # ...rest of the original with-block body, replacing any usage of csr_der
          {:error, _} = error ->
            error
        end
```

where `algorithm` is the algorithm id string (e.g. `"KAZ-SIGN-192"`) — look up the nearest variable in scope; the existing code has `level` as an integer, which needs mapping back to the string id. If the existing code has a variant/level, derive the algorithm id via `"KAZ-SIGN-#{level}"`.

Add a small helper if not present:

```elixir
  defp pem_to_der(pem) do
    [{_, der, _}] = :public_key.pem_decode(pem)
    der
  end
```

Place it near other private helpers.

- [ ] **Step 3: Run tests**

```
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_portal && mix test 2>&1 | tail -10
```

Expected: pass.

- [ ] **Step 4: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki
git add src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/direct.ex
git commit -m "refactor(pki_ca_portal): replace KazSign.generate_csr with PkiCrypto.Csr.generate"
```

---

## Task 7: Integration test — cross-algorithm matrix

**Files:**
- Create: `src/pki_crypto/test/pki_crypto/integration/pqc_issuer_test.exs`

- [ ] **Step 1: Write the test**

Create the file:

```elixir
defmodule PkiCrypto.Integration.PqcIssuerTest do
  use ExUnit.Case, async: true

  alias PkiCrypto.{Csr, X509Builder}

  describe "PQC issuer matrix" do
    test "KAZ-SIGN-192 root → ECDSA-P256 sub → verifies" do
      {:ok, root_cert_der, root_priv, root_pub, root_algo} = build_pqc_root("KAZ-SIGN-192", "/CN=KAZ Root")

      sub_priv = X509.PrivateKey.new_ec(:secp256r1)
      {:ok, csr_pem} = Csr.generate("ECC-P256", sub_priv, "/CN=ECDSA Sub")
      {:ok, csr} = Csr.parse(csr_pem)
      assert :ok = Csr.verify_pop(csr)

      {:ok, tbs, _} =
        X509Builder.build_tbs_cert(
          csr,
          %{cert_der: root_cert_der, algorithm_id: "KAZ-SIGN-192"},
          "/CN=ECDSA Sub",
          365,
          7001
        )

      {:ok, cert_der} = X509Builder.sign_tbs(tbs, "KAZ-SIGN-192", root_priv)

      {outer, <<>>} = PkiCrypto.Asn1.read_sequence(cert_der)
      [_tbs_back, _sig_alg, sig_bits] = PkiCrypto.Asn1.read_sequence_items(outer)
      {signature, <<>>} = PkiCrypto.Asn1.read_bit_string(sig_bits)

      assert :ok = PkiCrypto.Algorithm.verify(root_algo, root_pub, signature, tbs)
    end

    test "ML-DSA-65 root → KAZ-SIGN-128 leaf → verifies" do
      {:ok, root_cert_der, root_priv, root_pub, root_algo} = build_pqc_root("ML-DSA-65", "/CN=ML-DSA Root")

      leaf_algo = PkiCrypto.Registry.get("KAZ-SIGN-128")
      {:ok, %{public_key: leaf_pub, private_key: leaf_priv}} =
        PkiCrypto.Algorithm.generate_keypair(leaf_algo)

      {:ok, csr_pem} =
        Csr.generate("KAZ-SIGN-128", %{public_key: leaf_pub, private_key: leaf_priv}, "/CN=KAZ Leaf")

      {:ok, csr} = Csr.parse(csr_pem)
      assert :ok = Csr.verify_pop(csr)

      {:ok, tbs, _} =
        X509Builder.build_tbs_cert(
          csr,
          %{cert_der: root_cert_der, algorithm_id: "ML-DSA-65"},
          "/CN=KAZ Leaf",
          365,
          7002
        )

      {:ok, cert_der} = X509Builder.sign_tbs(tbs, "ML-DSA-65", root_priv)

      {outer, <<>>} = PkiCrypto.Asn1.read_sequence(cert_der)
      [_tbs_back, _sig_alg, sig_bits] = PkiCrypto.Asn1.read_sequence_items(outer)
      {signature, <<>>} = PkiCrypto.Asn1.read_bit_string(sig_bits)

      assert :ok = PkiCrypto.Algorithm.verify(root_algo, root_pub, signature, tbs)
    end
  end

  defp build_pqc_root(algorithm_id, subject_dn) do
    algo = PkiCrypto.Registry.get(algorithm_id)
    {:ok, %{public_key: pub, private_key: priv}} = PkiCrypto.Algorithm.generate_keypair(algo)

    {:ok, cert_der} =
      X509Builder.self_sign(algorithm_id, %{public_key: pub, private_key: priv}, subject_dn, 3650)

    {:ok, cert_der, priv, pub, algo}
  end
end
```

- [ ] **Step 2: Run**

```
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_crypto && mix test test/pki_crypto/integration/pqc_issuer_test.exs
```

Expected: 2 tests, 2 passed.

- [ ] **Step 3: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki
git add src/pki_crypto/test/pki_crypto/integration/pqc_issuer_test.exs
git commit -m "test(pki_crypto): integration — PQC issuer signs classical + cross-PQC"
```

---

## Task 8: Umbrella regression

- [ ] **Step 1: Run each app**

```
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_crypto && mix test 2>&1 | tail -3
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_engine && mix test 2>&1 | tail -3
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_validation && mix test 2>&1 | tail -3
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_portal && mix test 2>&1 | tail -3
```

Expected: zero failures in all four. Phase 3 should not regress any existing test.

- [ ] **Step 2: Umbrella compile**

```
cd /Users/amirrudinyahaya/Workspace/pki && mix compile 2>&1 | tail -10
```

Expected: clean. No new warnings from Phase 3 edits.

No commit — verification only. If regressions surface, fix at source before proceeding to VPS.

---

## Task 9: VPS deploy + live ceremony test

This is the real proof: the comp-5 sub-CA (KAZ-SIGN-192) ceremony from earlier in the day should now emit a real X.509 CSR that the ECDSA-P384 root can sign without `:invalid_csr_no_public_key`.

- [ ] **Step 1: Merge + push + deploy**

```bash
# local
git checkout main
git merge --no-ff feat/phase3-pqc-issuer-path -m "Merge phase 3: PQC issuer + JSON retirement"
git push

# VPS
cd ~/pki && git pull
set -a; source <(sudo cat /opt/pki/.env); set +a
sudo rm -rf _build/prod/rel
bash deploy/build.sh 2>&1 | tail -3
sudo bash deploy/deploy.sh 2>&1 | tail -10
sleep 15
sudo systemctl is-active pki-engines pki-portals pki-audit
```

Expected: all three active.

- [ ] **Step 2: Eval smoke test — PQC root signs classical sub**

```bash
sudo -u pki bash -c "set -a; source /opt/pki/.env; set +a; /opt/pki/releases/portals/bin/pki_portals eval '
  alias PkiCrypto.{Csr, X509Builder}

  algo = PkiCrypto.Registry.get(\"KAZ-SIGN-192\")
  {:ok, %{public_key: root_pub, private_key: root_priv}} = PkiCrypto.Algorithm.generate_keypair(algo)
  {:ok, root_cert_der} = X509Builder.self_sign(\"KAZ-SIGN-192\", %{public_key: root_pub, private_key: root_priv}, \"/CN=Phase3 KAZ Root\", 3650)

  sub_priv = X509.PrivateKey.new_ec(:secp384r1)
  {:ok, csr_pem} = Csr.generate(\"ECC-P384\", sub_priv, \"/CN=Phase3 Sub\")
  {:ok, csr} = Csr.parse(csr_pem)
  :ok = Csr.verify_pop(csr)

  {:ok, tbs, _} = X509Builder.build_tbs_cert(csr, %{cert_der: root_cert_der, algorithm_id: \"KAZ-SIGN-192\"}, \"/CN=Phase3 Sub\", 365, 777)
  {:ok, cert_der} = X509Builder.sign_tbs(tbs, \"KAZ-SIGN-192\", root_priv)

  IO.puts(\"phase3_smoke=\" <> to_string(byte_size(cert_der)) <> \" bytes\")
'"
```

Expected output line: `phase3_smoke=<N> bytes` with N > 0.

- [ ] **Step 3: Live ceremony test in the CA portal**

Using the existing comp-5 sub-CA (KAZ-SIGN-192):

1. Log in to `ca.straptrust.com` as comp-5 CA admin.
2. Go to **Issuer Keys**, find the sub-CA key (KAZ-SIGN-192).
3. Click **Generate CSR** — should now emit a real PKCS#10 PEM.
4. On the root CA (ECC-P384), **Sign CSR** with the generated PEM.
5. Click **Activate** on the sub-CA key and paste the returned cert PEM.

Success = sub-CA status transitions to `active`. No crash. No `:invalid_csr_no_public_key`.

If step 3 errors, check portal logs:
```
sudo journalctl -u pki-portals --since "2 minutes ago" --no-pager | tail -40
```

- [ ] **Step 4: Definition of done**

Phase 3 is complete when:

- `X509Builder.sign_tbs/3` supports all three PQC families + `self_sign/4` produces real X.509 root certs.
- `CertificateSigning.do_sign/6` routes every issuer algorithm through the unified orchestrator.
- No JSON-wrapper cert format remains in the codebase (`do_sign_kaz`, `do_sign_ml_dsa`, `generate_pqc_csr`, `generate_pqc_self_signed`, `KazSign.self_sign`, `KazSign.generate_csr` callers all deleted).
- Cross-algorithm matrix integration tests green (all four combos B/C/D/classical).
- VPS smoke + live comp-5 ceremony both succeed.

---

## Out-of-scope reminders

- **OCSP/CRL PQC signing** — Phase 4. `PkiValidation.SigningKeyStore` still doesn't load PQC keys; that wiring is the next and final phase.
- **Hybrid composite signatures** — deferred; not planned.
- **IANA PEN assignment for KAZ-SIGN** — config override ready; awaiting external allocation.

## Exit signal

When Phase 3 ships, the product fully supports cross-algorithm certificate issuance in RFC 5280 X.509 format. Only revocation (OCSP/CRL) in PQC remains for product completeness.
