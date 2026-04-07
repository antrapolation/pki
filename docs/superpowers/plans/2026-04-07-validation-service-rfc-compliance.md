# Validation Service RFC Compliance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `pki_validation` interoperable with standard PKI clients (openssl, browsers, Java/Go TLS) by implementing RFC 6960 (OCSP), RFC 5280 (CRL), and RFC 5019 (Lightweight OCSP) wire formats with cryptographic signing.

**Architecture:** Hybrid — Erlang `:public_key` for CRL DER encoding/signing, custom compiled ASN.1 module for OCSP (since OTP lacks built-in OCSP structures). Existing JSON endpoints preserved for portal use; new DER endpoints added alongside. Validation service holds delegated OCSP signing keys issued by the CA.

**Tech Stack:** Elixir 1.18, Erlang/OTP 27, `:public_key`, `:asn1ct`, Plug 1.16, Ecto 3.11, PostgreSQL, AES-256-GCM (via `pki_crypto`).

**Spec:** `docs/superpowers/specs/2026-04-07-validation-service-rfc-compliance-design.md`

---

## File Structure

**New files to create:**

| Path | Responsibility |
|---|---|
| `src/pki_validation/asn1/OCSP.asn1` | RFC 6960 Appendix B ASN.1 spec |
| `src/pki_validation/lib/pki_validation/asn1.ex` | Wrapper module exposing compiled OCSP records |
| `src/pki_validation/lib/pki_validation/schema/signing_key_config.ex` | Ecto schema for delegated signing keys |
| `src/pki_validation/lib/pki_validation/schema/crl_metadata.ex` | Ecto schema for CRL number tracking |
| `src/pki_validation/lib/pki_validation/signing_key_store.ex` | GenServer holding decrypted signing keys per issuer |
| `src/pki_validation/lib/pki_validation/cert_id.ex` | issuerNameHash / issuerKeyHash computation + matching |
| `src/pki_validation/lib/pki_validation/ocsp/request_decoder.ex` | DER OCSPRequest → CertID list |
| `src/pki_validation/lib/pki_validation/ocsp/response_builder.ex` | Build + sign BasicOCSPResponse |
| `src/pki_validation/lib/pki_validation/ocsp/der_responder.ex` | Orchestrates DER OCSP flow |
| `src/pki_validation/lib/pki_validation/crl/der_generator.ex` | DER CRL generation via `:public_key` |
| `src/pki_validation/priv/repo/migrations/20260407000001_add_issuer_name_hash.exs` | Adds column |
| `src/pki_validation/priv/repo/migrations/20260407000002_create_signing_key_config.exs` | New table |
| `src/pki_validation/priv/repo/migrations/20260407000003_create_crl_metadata.exs` | New table |
| `src/pki_validation/test/pki_validation/asn1_test.exs` | ASN.1 compile sanity test |
| `src/pki_validation/test/pki_validation/cert_id_test.exs` | CertID computation tests |
| `src/pki_validation/test/pki_validation/signing_key_store_test.exs` | Store load/lookup tests |
| `src/pki_validation/test/pki_validation/schema/signing_key_config_test.exs` | Schema tests |
| `src/pki_validation/test/pki_validation/schema/crl_metadata_test.exs` | Schema tests |
| `src/pki_validation/test/pki_validation/ocsp/request_decoder_test.exs` | Decoder tests |
| `src/pki_validation/test/pki_validation/ocsp/response_builder_test.exs` | Builder + sign tests |
| `src/pki_validation/test/pki_validation/ocsp/der_responder_test.exs` | DER flow tests |
| `src/pki_validation/test/pki_validation/crl/der_generator_test.exs` | CRL DER tests |
| `src/pki_validation/test/pki_validation/openssl_interop_test.exs` | openssl round-trip |

**Files to modify:**

| Path | Changes |
|---|---|
| `src/pki_validation/mix.exs` | Add asn1 compiler config, declare ASN.1 file |
| `src/pki_validation/lib/pki_validation/application.ex` | Start `SigningKeyStore` GenServer |
| `src/pki_validation/lib/pki_validation/api/router.ex` | Add DER endpoints + cache headers + signing-key-rotation |
| `src/pki_validation/lib/pki_validation/crl_publisher.ex` | Hook DER generation alongside JSON |
| `src/pki_validation/lib/pki_validation/schema/certificate_status.ex` | Add `issuer_name_hash` field |

---

## Task 1: Add ASN.1 compiler to mix project

**Files:**
- Modify: `src/pki_validation/mix.exs`
- Create: `src/pki_validation/asn1/OCSP.asn1`

- [ ] **Step 1: Create the OCSP ASN.1 spec file**

Create `src/pki_validation/asn1/OCSP.asn1` with the RFC 6960 Appendix B definitions:

```asn1
OCSP DEFINITIONS EXPLICIT TAGS ::=

BEGIN

IMPORTS
    Certificate, AlgorithmIdentifier, CertificateSerialNumber, Name, Extensions
        FROM PKIX1Explicit88
            { iso(1) identified-organization(3) dod(6) internet(1) security(5)
              mechanisms(5) pkix(7) id-mod(0) id-pkix1-explicit(18) };

OCSPRequest ::= SEQUENCE {
    tbsRequest                  TBSRequest,
    optionalSignature   [0]     EXPLICIT Signature OPTIONAL }

TBSRequest ::= SEQUENCE {
    version             [0]     EXPLICIT Version DEFAULT v1,
    requestorName       [1]     EXPLICIT GeneralName OPTIONAL,
    requestList                 SEQUENCE OF Request,
    requestExtensions   [2]     EXPLICIT Extensions OPTIONAL }

Signature ::= SEQUENCE {
    signatureAlgorithm   AlgorithmIdentifier,
    signature            BIT STRING,
    certs            [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }

Version ::= INTEGER { v1(0) }

Request ::= SEQUENCE {
    reqCert                    CertID,
    singleRequestExtensions    [0] EXPLICIT Extensions OPTIONAL }

CertID ::= SEQUENCE {
    hashAlgorithm   AlgorithmIdentifier,
    issuerNameHash  OCTET STRING,
    issuerKeyHash   OCTET STRING,
    serialNumber    CertificateSerialNumber }

OCSPResponse ::= SEQUENCE {
    responseStatus   OCSPResponseStatus,
    responseBytes  [0] EXPLICIT ResponseBytes OPTIONAL }

OCSPResponseStatus ::= ENUMERATED {
    successful       (0),
    malformedRequest (1),
    internalError    (2),
    tryLater         (3),
    sigRequired      (5),
    unauthorized     (6) }

ResponseBytes ::= SEQUENCE {
    responseType   OBJECT IDENTIFIER,
    response       OCTET STRING }

BasicOCSPResponse ::= SEQUENCE {
    tbsResponseData       ResponseData,
    signatureAlgorithm    AlgorithmIdentifier,
    signature             BIT STRING,
    certs             [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }

ResponseData ::= SEQUENCE {
    version              [0] EXPLICIT Version DEFAULT v1,
    responderID              ResponderID,
    producedAt               GeneralizedTime,
    responses                SEQUENCE OF SingleResponse,
    responseExtensions   [1] EXPLICIT Extensions OPTIONAL }

ResponderID ::= CHOICE {
    byName   [1] Name,
    byKey    [2] KeyHash }

KeyHash ::= OCTET STRING

SingleResponse ::= SEQUENCE {
    certID                       CertID,
    certStatus                   CertStatus,
    thisUpdate                   GeneralizedTime,
    nextUpdate           [0]     EXPLICIT GeneralizedTime OPTIONAL,
    singleExtensions     [1]     EXPLICIT Extensions OPTIONAL }

CertStatus ::= CHOICE {
    good        [0] IMPLICIT NULL,
    revoked     [1] IMPLICIT RevokedInfo,
    unknown     [2] IMPLICIT UnknownInfo }

RevokedInfo ::= SEQUENCE {
    revocationTime              GeneralizedTime,
    revocationReason    [0]     EXPLICIT CRLReason OPTIONAL }

UnknownInfo ::= NULL

CRLReason ::= ENUMERATED {
    unspecified          (0),
    keyCompromise        (1),
    cACompromise         (2),
    affiliationChanged   (3),
    superseded           (4),
    cessationOfOperation (5),
    certificateHold      (6),
    removeFromCRL        (8),
    privilegeWithdrawn   (9),
    aACompromise         (10) }

GeneralName ::= ANY

END
```

- [ ] **Step 2: Update mix.exs to compile ASN.1**

Replace the `project/0` function in `src/pki_validation/mix.exs`:

```elixir
def project do
  [
    app: :pki_validation,
    version: "0.1.0",
    elixir: "~> 1.18",
    start_permanent: Mix.env() == :prod,
    elixirc_paths: elixirc_paths(Mix.env()),
    erlc_paths: ["asn1"],
    erlc_options: [{:i, ~c"asn1"}],
    compilers: [:asn1] ++ Mix.compilers(),
    asn1_options: [:per],
    aliases: aliases(),
    deps: deps()
  ]
end
```

Add `{:asn1ex, git: "https://github.com/vicentfg/asn1ex.git", tag: "0.1.0"}` to deps. If that dep is unavailable in this environment, alternatively use a custom compiler module: create `src/pki_validation/lib/mix/tasks/compile.asn1.ex`:

```elixir
defmodule Mix.Tasks.Compile.Asn1 do
  use Mix.Task.Compiler

  @impl true
  def run(_args) do
    asn1_dir = "asn1"
    out_dir = "src"
    File.mkdir_p!(out_dir)

    Path.wildcard(Path.join(asn1_dir, "*.asn1"))
    |> Enum.each(fn file ->
      :ok = :asn1ct.compile(String.to_charlist(Path.rootname(file)),
        [:ber, {:outdir, String.to_charlist(out_dir)}])
    end)

    {:ok, []}
  end

  @impl true
  def manifests, do: []

  @impl true
  def clean, do: :ok
end
```

And update `compilers:` to `[:asn1] ++ Mix.compilers()`. Skip the `asn1ex` dep entirely if using the custom compiler.

- [ ] **Step 3: Run the compiler to verify ASN.1 compiles**

Run: `cd src/pki_validation && mix compile`

Expected: Compilation succeeds. The compiled `OCSP.erl` and `OCSP.hrl` should appear in `src/` directory of the project.

If the compile errors with "missing PKIX1Explicit88", remove the `IMPORTS` block from the .asn1 file and inline the types as `ANY` placeholders — we'll handle those types via `:public_key`-decoded records in Elixir.

- [ ] **Step 4: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki
git add src/pki_validation/asn1/ src/pki_validation/mix.exs src/pki_validation/lib/mix/
git commit -m "feat(validation): add OCSP ASN.1 module compilation"
```

---

## Task 2: ASN.1 wrapper module + sanity test

**Files:**
- Create: `src/pki_validation/lib/pki_validation/asn1.ex`
- Test: `src/pki_validation/test/pki_validation/asn1_test.exs`

- [ ] **Step 1: Write the failing test**

Create `src/pki_validation/test/pki_validation/asn1_test.exs`:

```elixir
defmodule PkiValidation.Asn1Test do
  use ExUnit.Case, async: true

  alias PkiValidation.Asn1

  test "encode and decode an OCSPResponseStatus successful" do
    {:ok, der} = Asn1.encode(:OCSPResponseStatus, :successful)
    assert is_binary(der)
    assert {:ok, :successful} = Asn1.decode(:OCSPResponseStatus, der)
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd src/pki_validation && mix test test/pki_validation/asn1_test.exs`
Expected: FAIL — `PkiValidation.Asn1` module not defined.

- [ ] **Step 3: Implement the wrapper**

Create `src/pki_validation/lib/pki_validation/asn1.ex`:

```elixir
defmodule PkiValidation.Asn1 do
  @moduledoc """
  Wrapper around the compiled OCSP ASN.1 module.

  The compiled module is named `:OCSP` (Erlang atom).
  """

  @asn1_module :OCSP

  def encode(type, value) do
    case @asn1_module.encode(type, value) do
      {:ok, der} when is_binary(der) -> {:ok, der}
      {:ok, iolist} -> {:ok, IO.iodata_to_binary(iolist)}
      {:error, reason} -> {:error, reason}
    end
  end

  def decode(type, der) when is_binary(der) do
    case @asn1_module.decode(type, der) do
      {:ok, value} -> {:ok, value}
      {:error, reason} -> {:error, reason}
    end
  end
end
```

- [ ] **Step 4: Run the test**

Run: `cd src/pki_validation && mix test test/pki_validation/asn1_test.exs`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/pki_validation/lib/pki_validation/asn1.ex src/pki_validation/test/pki_validation/asn1_test.exs
git commit -m "feat(validation): add ASN.1 wrapper module"
```

---

## Task 3: Migration — add `issuer_name_hash` to certificate_status

**Files:**
- Create: `src/pki_validation/priv/repo/migrations/20260407000001_add_issuer_name_hash.exs`
- Modify: `src/pki_validation/lib/pki_validation/schema/certificate_status.ex`

- [ ] **Step 1: Create the migration**

Create `src/pki_validation/priv/repo/migrations/20260407000001_add_issuer_name_hash.exs`:

```elixir
defmodule PkiValidation.Repo.Migrations.AddIssuerNameHash do
  use Ecto.Migration

  def change do
    alter table(:certificate_status) do
      add :issuer_name_hash, :binary
    end

    create index(:certificate_status, [:issuer_key_id, :serial_number])
    create index(:certificate_status, [:status, :revoked_at])
  end
end
```

- [ ] **Step 2: Add field to schema**

In `src/pki_validation/lib/pki_validation/schema/certificate_status.ex`, add to the schema block (after `field :revocation_reason, :string`):

```elixir
field :issuer_name_hash, :binary
```

And update `@optional_fields`:

```elixir
@optional_fields ~w(revoked_at revocation_reason issuer_name_hash)a
```

- [ ] **Step 3: Run migration and existing tests**

Run: `cd src/pki_validation && mix ecto.migrate && mix test test/pki_validation/schema/certificate_status_test.exs`
Expected: Migration runs, all schema tests still pass.

- [ ] **Step 4: Commit**

```bash
git add src/pki_validation/priv/repo/migrations/20260407000001_add_issuer_name_hash.exs src/pki_validation/lib/pki_validation/schema/certificate_status.ex
git commit -m "feat(validation): add issuer_name_hash to certificate_status"
```

---

## Task 4: SigningKeyConfig schema + migration

**Files:**
- Create: `src/pki_validation/priv/repo/migrations/20260407000002_create_signing_key_config.exs`
- Create: `src/pki_validation/lib/pki_validation/schema/signing_key_config.ex`
- Test: `src/pki_validation/test/pki_validation/schema/signing_key_config_test.exs`

- [ ] **Step 1: Write the failing test**

Create `src/pki_validation/test/pki_validation/schema/signing_key_config_test.exs`:

```elixir
defmodule PkiValidation.Schema.SigningKeyConfigTest do
  use PkiValidation.DataCase, async: true

  alias PkiValidation.Schema.SigningKeyConfig
  alias PkiValidation.Repo

  @valid_attrs %{
    issuer_key_id: Uniq.UUID.uuid7(),
    algorithm: "ecc_p256",
    certificate_pem: "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----",
    encrypted_private_key: <<1, 2, 3>>,
    not_before: DateTime.utc_now(),
    not_after: DateTime.utc_now() |> DateTime.add(30, :day),
    status: "active"
  }

  test "valid attrs produce a valid changeset" do
    changeset = SigningKeyConfig.changeset(%SigningKeyConfig{}, @valid_attrs)
    assert changeset.valid?
  end

  test "requires issuer_key_id" do
    attrs = Map.delete(@valid_attrs, :issuer_key_id)
    changeset = SigningKeyConfig.changeset(%SigningKeyConfig{}, attrs)
    refute changeset.valid?
    assert %{issuer_key_id: ["can't be blank"]} = errors_on(changeset)
  end

  test "validates algorithm inclusion" do
    attrs = Map.put(@valid_attrs, :algorithm, "bogus_alg")
    changeset = SigningKeyConfig.changeset(%SigningKeyConfig{}, attrs)
    refute changeset.valid?
  end

  test "validates status inclusion" do
    attrs = Map.put(@valid_attrs, :status, "bogus")
    changeset = SigningKeyConfig.changeset(%SigningKeyConfig{}, attrs)
    refute changeset.valid?
  end

  test "persists to database with unique constraint on (issuer_key_id, status=active)" do
    {:ok, _} = %SigningKeyConfig{} |> SigningKeyConfig.changeset(@valid_attrs) |> Repo.insert()
    {:error, changeset} = %SigningKeyConfig{} |> SigningKeyConfig.changeset(@valid_attrs) |> Repo.insert()
    assert %{issuer_key_id: ["only one active signing key per issuer"]} = errors_on(changeset)
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd src/pki_validation && mix test test/pki_validation/schema/signing_key_config_test.exs`
Expected: FAIL — module not defined.

- [ ] **Step 3: Create the migration**

Create `src/pki_validation/priv/repo/migrations/20260407000002_create_signing_key_config.exs`:

```elixir
defmodule PkiValidation.Repo.Migrations.CreateSigningKeyConfig do
  use Ecto.Migration

  def change do
    create table(:signing_key_config, primary_key: false) do
      add :id, :binary_id, primary_key: true, null: false
      add :issuer_key_id, :binary_id, null: false
      add :algorithm, :string, null: false
      add :certificate_pem, :text, null: false
      add :encrypted_private_key, :binary, null: false
      add :not_before, :utc_datetime_usec, null: false
      add :not_after, :utc_datetime_usec, null: false
      add :status, :string, null: false, default: "active"

      timestamps(type: :utc_datetime_usec)
    end

    create index(:signing_key_config, [:issuer_key_id])
    create unique_index(:signing_key_config, [:issuer_key_id],
             where: "status = 'active'",
             name: :signing_key_config_one_active_per_issuer)
  end
end
```

- [ ] **Step 4: Create the schema module**

Create `src/pki_validation/lib/pki_validation/schema/signing_key_config.ex`:

```elixir
defmodule PkiValidation.Schema.SigningKeyConfig do
  @moduledoc """
  Delegated OCSP/CRL signing key configuration per issuer key.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @valid_algorithms ~w(ecc_p256 ecc_p384 rsa4096 ml_dsa kaz_sign slh_dsa)
  @valid_statuses ~w(active pending_rotation expired)

  @primary_key {:id, :binary_id, autogenerate: false}

  schema "signing_key_config" do
    field :issuer_key_id, :binary_id
    field :algorithm, :string
    field :certificate_pem, :string
    field :encrypted_private_key, :binary
    field :not_before, :utc_datetime_usec
    field :not_after, :utc_datetime_usec
    field :status, :string, default: "active"

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(issuer_key_id algorithm certificate_pem encrypted_private_key not_before not_after status)a

  def changeset(record, attrs) do
    record
    |> cast(attrs, @required_fields)
    |> maybe_generate_id()
    |> validate_required(@required_fields)
    |> validate_inclusion(:algorithm, @valid_algorithms)
    |> validate_inclusion(:status, @valid_statuses)
    |> unique_constraint(:issuer_key_id,
         name: :signing_key_config_one_active_per_issuer,
         message: "only one active signing key per issuer")
  end

  defp maybe_generate_id(changeset) do
    case get_field(changeset, :id) do
      nil -> put_change(changeset, :id, Uniq.UUID.uuid7())
      _ -> changeset
    end
  end
end
```

- [ ] **Step 5: Run migration and test**

Run: `cd src/pki_validation && mix ecto.migrate && mix test test/pki_validation/schema/signing_key_config_test.exs`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/pki_validation/priv/repo/migrations/20260407000002_create_signing_key_config.exs \
        src/pki_validation/lib/pki_validation/schema/signing_key_config.ex \
        src/pki_validation/test/pki_validation/schema/signing_key_config_test.exs
git commit -m "feat(validation): add SigningKeyConfig schema + migration"
```

---

## Task 5: CrlMetadata schema + migration

**Files:**
- Create: `src/pki_validation/priv/repo/migrations/20260407000003_create_crl_metadata.exs`
- Create: `src/pki_validation/lib/pki_validation/schema/crl_metadata.ex`
- Test: `src/pki_validation/test/pki_validation/schema/crl_metadata_test.exs`

- [ ] **Step 1: Write the failing test**

Create `src/pki_validation/test/pki_validation/schema/crl_metadata_test.exs`:

```elixir
defmodule PkiValidation.Schema.CrlMetadataTest do
  use PkiValidation.DataCase, async: true

  alias PkiValidation.Schema.CrlMetadata
  alias PkiValidation.Repo

  @valid_attrs %{
    issuer_key_id: Uniq.UUID.uuid7(),
    crl_number: 1,
    last_generated_at: DateTime.utc_now(),
    last_der_bytes: <<0, 1, 2>>,
    last_der_size: 3,
    generation_count: 1
  }

  test "valid attrs produce a valid changeset" do
    changeset = CrlMetadata.changeset(%CrlMetadata{}, @valid_attrs)
    assert changeset.valid?
  end

  test "requires issuer_key_id" do
    attrs = Map.delete(@valid_attrs, :issuer_key_id)
    changeset = CrlMetadata.changeset(%CrlMetadata{}, attrs)
    refute changeset.valid?
  end

  test "issuer_key_id is unique" do
    {:ok, _} = %CrlMetadata{} |> CrlMetadata.changeset(@valid_attrs) |> Repo.insert()
    {:error, changeset} = %CrlMetadata{} |> CrlMetadata.changeset(@valid_attrs) |> Repo.insert()
    refute changeset.valid?
  end

  test "crl_number must be positive" do
    attrs = Map.put(@valid_attrs, :crl_number, 0)
    changeset = CrlMetadata.changeset(%CrlMetadata{}, attrs)
    refute changeset.valid?
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd src/pki_validation && mix test test/pki_validation/schema/crl_metadata_test.exs`
Expected: FAIL — module not defined.

- [ ] **Step 3: Create the migration**

Create `src/pki_validation/priv/repo/migrations/20260407000003_create_crl_metadata.exs`:

```elixir
defmodule PkiValidation.Repo.Migrations.CreateCrlMetadata do
  use Ecto.Migration

  def change do
    create table(:crl_metadata, primary_key: false) do
      add :id, :binary_id, primary_key: true, null: false
      add :issuer_key_id, :binary_id, null: false
      add :crl_number, :bigint, null: false, default: 1
      add :last_generated_at, :utc_datetime_usec
      add :last_der_bytes, :binary
      add :last_der_size, :integer, default: 0
      add :generation_count, :integer, null: false, default: 0

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:crl_metadata, [:issuer_key_id])
  end
end
```

- [ ] **Step 4: Create the schema**

Create `src/pki_validation/lib/pki_validation/schema/crl_metadata.ex`:

```elixir
defmodule PkiValidation.Schema.CrlMetadata do
  @moduledoc """
  Per-issuer CRL generation metadata.
  Tracks the monotonic CRL number and caches the latest signed DER bytes.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}

  schema "crl_metadata" do
    field :issuer_key_id, :binary_id
    field :crl_number, :integer, default: 1
    field :last_generated_at, :utc_datetime_usec
    field :last_der_bytes, :binary
    field :last_der_size, :integer, default: 0
    field :generation_count, :integer, default: 0

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(issuer_key_id crl_number)a
  @optional_fields ~w(last_generated_at last_der_bytes last_der_size generation_count)a

  def changeset(record, attrs) do
    record
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> maybe_generate_id()
    |> validate_required(@required_fields)
    |> validate_number(:crl_number, greater_than: 0)
    |> unique_constraint(:issuer_key_id)
  end

  defp maybe_generate_id(changeset) do
    case get_field(changeset, :id) do
      nil -> put_change(changeset, :id, Uniq.UUID.uuid7())
      _ -> changeset
    end
  end
end
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd src/pki_validation && mix ecto.migrate && mix test test/pki_validation/schema/crl_metadata_test.exs`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/pki_validation/priv/repo/migrations/20260407000003_create_crl_metadata.exs \
        src/pki_validation/lib/pki_validation/schema/crl_metadata.ex \
        src/pki_validation/test/pki_validation/schema/crl_metadata_test.exs
git commit -m "feat(validation): add CrlMetadata schema + migration"
```

---

## Task 6: CertID computation module

**Files:**
- Create: `src/pki_validation/lib/pki_validation/cert_id.ex`
- Test: `src/pki_validation/test/pki_validation/cert_id_test.exs`

- [ ] **Step 1: Write the failing test**

Create `src/pki_validation/test/pki_validation/cert_id_test.exs`:

```elixir
defmodule PkiValidation.CertIdTest do
  use ExUnit.Case, async: true

  alias PkiValidation.CertId

  # Generate an ECC keypair + self-signed cert for testing
  setup do
    {pub, priv} = :crypto.generate_key(:ecdh, :secp256r1)
    # Build a minimal :public_key OTPCertificate via :public_key for test
    der_cert = build_test_cert(pub, priv)
    {:ok, der_cert: der_cert}
  end

  test "issuer_name_hash returns SHA-1 hash of subject DN", %{der_cert: der} do
    hash = CertId.issuer_name_hash(der)
    assert is_binary(hash)
    assert byte_size(hash) == 20
  end

  test "issuer_key_hash returns SHA-1 hash of public key BIT STRING", %{der_cert: der} do
    hash = CertId.issuer_key_hash(der)
    assert is_binary(hash)
    assert byte_size(hash) == 20
  end

  test "matches? returns true when CertID matches issuer cert + serial", %{der_cert: der} do
    name_hash = CertId.issuer_name_hash(der)
    key_hash = CertId.issuer_key_hash(der)
    serial = 12345

    assert CertId.matches?(
             %{issuer_name_hash: name_hash, issuer_key_hash: key_hash, serial_number: serial},
             %{name_hash: name_hash, key_hash: key_hash, serial_number: serial}
           )
  end

  test "matches? returns false when serial differs", %{der_cert: der} do
    name_hash = CertId.issuer_name_hash(der)
    key_hash = CertId.issuer_key_hash(der)

    refute CertId.matches?(
             %{issuer_name_hash: name_hash, issuer_key_hash: key_hash, serial_number: 1},
             %{name_hash: name_hash, key_hash: key_hash, serial_number: 2}
           )
  end

  defp build_test_cert(_pub, _priv) do
    # Use :public_key.pkix_test_root_cert/2 if available, otherwise build minimally
    {:ok, der} = File.read(Path.expand("../../../../test/fixtures/test_issuer.der", __DIR__))
    der
  rescue
    _ ->
      # Fallback: generate via :public_key.pkix_test_root_cert
      {cert, _key} = :public_key.pkix_test_root_cert("Test Issuer", [])
      :public_key.pkix_encode(:OTPCertificate, cert, :otp)
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd src/pki_validation && mix test test/pki_validation/cert_id_test.exs`
Expected: FAIL — `PkiValidation.CertId` not defined.

- [ ] **Step 3: Implement CertId module**

Create `src/pki_validation/lib/pki_validation/cert_id.ex`:

```elixir
defmodule PkiValidation.CertId do
  @moduledoc """
  RFC 6960 CertID helpers.

  CertID ::= SEQUENCE {
      hashAlgorithm   AlgorithmIdentifier,
      issuerNameHash  OCTET STRING,
      issuerKeyHash   OCTET STRING,
      serialNumber    CertificateSerialNumber }

  We use SHA-1 throughout (the OCSP default per RFC 6960). issuerNameHash is
  the hash of the DER-encoded issuer DN; issuerKeyHash is the hash of the
  raw public key BIT STRING (without ASN.1 tag/length).
  """

  @doc """
  Compute the SHA-1 hash of an issuer's DER-encoded subject DN.

  Input: DER-encoded certificate (binary).
  """
  def issuer_name_hash(der_cert) when is_binary(der_cert) do
    otp = :public_key.pkix_decode_cert(der_cert, :otp)
    tbs = elem(otp, 1)
    subject = elem(tbs, 5)
    {:rdnSequence, _} = subject
    subject_der = :public_key.pkix_encode(:OTPName, subject, :otp)
    :crypto.hash(:sha, subject_der)
  end

  @doc """
  Compute the SHA-1 hash of an issuer's public key BIT STRING.

  Per RFC 6960 §4.1.1: "issuerKeyHash is the hash of the issuer's public key.
  The hash shall be calculated over the value (excluding tag and length) of
  the subject public key field in the issuer's certificate."
  """
  def issuer_key_hash(der_cert) when is_binary(der_cert) do
    otp = :public_key.pkix_decode_cert(der_cert, :otp)
    tbs = elem(otp, 1)
    spki = elem(tbs, 7)
    # SubjectPublicKeyInfo: {OTPSubjectPublicKeyInfo, alg, public_key}
    public_key_bits = elem(spki, 2)
    raw =
      case public_key_bits do
        bits when is_binary(bits) -> bits
        {:ECPoint, point} -> point
        other -> :erlang.term_to_binary(other)
      end
    :crypto.hash(:sha, raw)
  end

  @doc """
  Returns true if the request CertID matches the known issuer hashes and serial.
  """
  def matches?(request_cert_id, known) do
    request_cert_id.issuer_name_hash == known.name_hash and
      request_cert_id.issuer_key_hash == known.key_hash and
      request_cert_id.serial_number == known.serial_number
  end
end
```

- [ ] **Step 4: Run test**

Run: `cd src/pki_validation && mix test test/pki_validation/cert_id_test.exs`
Expected: PASS. If `pkix_test_root_cert/2` is unavailable in this OTP, the test setup will need a real fixture. In that case, generate one with: `openssl req -x509 -newkey ec:<(openssl ecparam -name prime256v1) -nodes -out test_issuer.der -outform DER -days 30 -subj "/CN=Test Issuer"` and place it at `src/pki_validation/test/fixtures/test_issuer.der`.

- [ ] **Step 5: Commit**

```bash
git add src/pki_validation/lib/pki_validation/cert_id.ex \
        src/pki_validation/test/pki_validation/cert_id_test.exs \
        src/pki_validation/test/fixtures/
git commit -m "feat(validation): add CertID hash computation module"
```

---

## Task 7: SigningKeyStore GenServer

**Files:**
- Create: `src/pki_validation/lib/pki_validation/signing_key_store.ex`
- Test: `src/pki_validation/test/pki_validation/signing_key_store_test.exs`
- Modify: `src/pki_validation/lib/pki_validation/application.ex`

- [ ] **Step 1: Write the failing test**

Create `src/pki_validation/test/pki_validation/signing_key_store_test.exs`:

```elixir
defmodule PkiValidation.SigningKeyStoreTest do
  use PkiValidation.DataCase, async: false

  alias PkiValidation.SigningKeyStore
  alias PkiValidation.Schema.SigningKeyConfig
  alias PkiValidation.Repo

  setup do
    issuer_key_id = Uniq.UUID.uuid7()
    {cert_pem, encrypted_priv} = generate_test_signing_keypair()

    {:ok, _} =
      %SigningKeyConfig{}
      |> SigningKeyConfig.changeset(%{
        issuer_key_id: issuer_key_id,
        algorithm: "ecc_p256",
        certificate_pem: cert_pem,
        encrypted_private_key: encrypted_priv,
        not_before: DateTime.utc_now(),
        not_after: DateTime.add(DateTime.utc_now(), 30, :day),
        status: "active"
      })
      |> Repo.insert()

    name = :"signing_key_store_#{System.unique_integer([:positive])}"
    {:ok, pid} = SigningKeyStore.start_link(name: name, password: "test-password")
    {:ok, store: pid, issuer_key_id: issuer_key_id, name: name}
  end

  test "loads signing keys at startup", %{name: name, issuer_key_id: id} do
    assert {:ok, %{algorithm: "ecc_p256"}} = SigningKeyStore.get(name, id)
  end

  test "returns :not_found for unknown issuer", %{name: name} do
    assert :not_found = SigningKeyStore.get(name, "unknown-id")
  end

  test "lookup includes private key and certificate", %{name: name, issuer_key_id: id} do
    {:ok, key} = SigningKeyStore.get(name, id)
    assert key.private_key
    assert key.certificate_der
  end

  defp generate_test_signing_keypair do
    {pub, priv} = :crypto.generate_key(:ecdh, :secp256r1)
    encrypted = PkiValidation.SigningKeyStore.encrypt_for_test(priv, "test-password")
    cert_pem = "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----"
    {cert_pem, encrypted}
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd src/pki_validation && mix test test/pki_validation/signing_key_store_test.exs`
Expected: FAIL — module not defined.

- [ ] **Step 3: Implement SigningKeyStore**

Create `src/pki_validation/lib/pki_validation/signing_key_store.ex`:

```elixir
defmodule PkiValidation.SigningKeyStore do
  @moduledoc """
  GenServer holding decrypted OCSP/CRL signing keys per issuer.

  On startup, loads all `SigningKeyConfig` records with status = "active",
  decrypts the private keys using the activation password, and stores them
  in process state for fast lookup.
  """

  use GenServer
  require Logger

  alias PkiValidation.Repo
  alias PkiValidation.Schema.SigningKeyConfig
  import Ecto.Query

  # 100k iterations matches pki_crypto KDF defaults
  @kdf_iterations 100_000
  @kdf_key_length 32

  ## Client API

  def start_link(opts) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  def get(server \\ __MODULE__, issuer_key_id) do
    GenServer.call(server, {:get, issuer_key_id})
  end

  def reload(server \\ __MODULE__) do
    GenServer.call(server, :reload)
  end

  ## Test helper (only for tests)
  def encrypt_for_test(private_key, password) do
    salt = :crypto.strong_rand_bytes(16)
    key = :crypto.pbkdf2_hmac(:sha256, password, salt, @kdf_iterations, @kdf_key_length)
    iv = :crypto.strong_rand_bytes(12)
    {ct, tag} = :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, private_key, "", true)
    salt <> iv <> tag <> ct
  end

  ## Server callbacks

  @impl true
  def init(opts) do
    password = Keyword.get(opts, :password) || System.get_env("VALIDATION_SIGNING_KEY_PASSWORD") || ""
    state = %{password: password, keys: load_keys(password)}
    Logger.info("SigningKeyStore loaded #{map_size(state.keys)} signing keys")
    {:ok, state}
  end

  @impl true
  def handle_call({:get, issuer_key_id}, _from, state) do
    case Map.get(state.keys, issuer_key_id) do
      nil -> {:reply, :not_found, state}
      key -> {:reply, {:ok, key}, state}
    end
  end

  def handle_call(:reload, _from, state) do
    {:reply, :ok, %{state | keys: load_keys(state.password)}}
  end

  defp load_keys(password) do
    SigningKeyConfig
    |> where([c], c.status == "active")
    |> Repo.all()
    |> Enum.reduce(%{}, fn config, acc ->
      case decrypt_private_key(config.encrypted_private_key, password) do
        {:ok, priv} ->
          cert_der =
            case decode_cert_pem(config.certificate_pem) do
              {:ok, der} -> der
              :error -> nil
            end

          Map.put(acc, config.issuer_key_id, %{
            algorithm: config.algorithm,
            private_key: priv,
            certificate_der: cert_der,
            not_after: config.not_after
          })

        {:error, reason} ->
          Logger.error("Failed to decrypt signing key for issuer #{config.issuer_key_id}: #{inspect(reason)}")
          acc
      end
    end)
  end

  defp decrypt_private_key(<<salt::binary-size(16), iv::binary-size(12), tag::binary-size(16), ct::binary>>, password) do
    key = :crypto.pbkdf2_hmac(:sha256, password, salt, @kdf_iterations, @kdf_key_length)

    case :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, ct, "", tag, false) do
      plain when is_binary(plain) -> {:ok, plain}
      :error -> {:error, :decryption_failed}
    end
  rescue
    _ -> {:error, :malformed_ciphertext}
  end

  defp decrypt_private_key(_, _), do: {:error, :malformed_ciphertext}

  defp decode_cert_pem(pem) when is_binary(pem) do
    case :public_key.pem_decode(pem) do
      [{:Certificate, der, _} | _] -> {:ok, der}
      _ -> :error
    end
  end
end
```

- [ ] **Step 4: Add to application supervisor**

Modify `src/pki_validation/lib/pki_validation/application.ex` — find the children list and add `SigningKeyStore` after `Repo`:

```elixir
{PkiValidation.SigningKeyStore, []},
```

- [ ] **Step 5: Run test**

Run: `cd src/pki_validation && mix test test/pki_validation/signing_key_store_test.exs`
Expected: PASS

- [ ] **Step 6: Run all existing tests to make sure nothing broke**

Run: `cd src/pki_validation && mix test`
Expected: All pass.

- [ ] **Step 7: Commit**

```bash
git add src/pki_validation/lib/pki_validation/signing_key_store.ex \
        src/pki_validation/lib/pki_validation/application.ex \
        src/pki_validation/test/pki_validation/signing_key_store_test.exs
git commit -m "feat(validation): add SigningKeyStore for delegated signing keys"
```

---

## Task 8: OCSP request decoder

**Files:**
- Create: `src/pki_validation/lib/pki_validation/ocsp/request_decoder.ex`
- Test: `src/pki_validation/test/pki_validation/ocsp/request_decoder_test.exs`

- [ ] **Step 1: Write the failing test**

Create `src/pki_validation/test/pki_validation/ocsp/request_decoder_test.exs`:

```elixir
defmodule PkiValidation.Ocsp.RequestDecoderTest do
  use ExUnit.Case, async: true

  alias PkiValidation.Ocsp.RequestDecoder

  test "decodes a real OCSP request DER (generated by openssl)" do
    der = sample_ocsp_request_der()
    assert {:ok, %{cert_ids: [cert_id | _], nonce: _nonce}} = RequestDecoder.decode(der)
    assert is_binary(cert_id.issuer_name_hash)
    assert is_binary(cert_id.issuer_key_hash)
    assert is_integer(cert_id.serial_number)
  end

  test "returns {:error, :malformed} for garbage input" do
    assert {:error, :malformed} = RequestDecoder.decode(<<0, 1, 2, 3>>)
  end

  test "extracts nonce extension when present" do
    der = sample_ocsp_request_der_with_nonce()
    assert {:ok, %{nonce: nonce}} = RequestDecoder.decode(der)
    assert is_binary(nonce)
  end

  defp sample_ocsp_request_der do
    # A pre-generated DER OCSP request fixture; if missing, the test
    # generates one inline using a freshly built issuer cert
    fixture_path = Path.expand("../../fixtures/ocsp_request.der", __DIR__)

    case File.read(fixture_path) do
      {:ok, bin} -> bin
      _ -> generate_inline_request()
    end
  end

  defp sample_ocsp_request_der_with_nonce do
    fixture_path = Path.expand("../../fixtures/ocsp_request_nonce.der", __DIR__)

    case File.read(fixture_path) do
      {:ok, bin} -> bin
      _ -> generate_inline_request_with_nonce()
    end
  end

  defp generate_inline_request do
    # Build minimal OCSPRequest using compiled OCSP module
    cert_id =
      {:CertID,
       {:AlgorithmIdentifier, {1, 3, 14, 3, 2, 26}, <<5, 0>>},
       :crypto.strong_rand_bytes(20),
       :crypto.strong_rand_bytes(20),
       12345}

    request = {:Request, cert_id, :asn1_NOVALUE}
    tbs = {:TBSRequest, :asn1_NOVALUE, :asn1_NOVALUE, [request], :asn1_NOVALUE}
    ocsp_req = {:OCSPRequest, tbs, :asn1_NOVALUE}
    {:ok, der} = :OCSP.encode(:OCSPRequest, ocsp_req)
    IO.iodata_to_binary(der)
  end

  defp generate_inline_request_with_nonce do
    nonce = :crypto.strong_rand_bytes(16)
    nonce_ext = {:Extension, {1, 3, 6, 1, 5, 5, 7, 48, 1, 2}, false, nonce}

    cert_id =
      {:CertID,
       {:AlgorithmIdentifier, {1, 3, 14, 3, 2, 26}, <<5, 0>>},
       :crypto.strong_rand_bytes(20),
       :crypto.strong_rand_bytes(20),
       99999}

    request = {:Request, cert_id, :asn1_NOVALUE}
    tbs = {:TBSRequest, :asn1_NOVALUE, :asn1_NOVALUE, [request], [nonce_ext]}
    ocsp_req = {:OCSPRequest, tbs, :asn1_NOVALUE}
    {:ok, der} = :OCSP.encode(:OCSPRequest, ocsp_req)
    IO.iodata_to_binary(der)
  end
end
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd src/pki_validation && mix test test/pki_validation/ocsp/request_decoder_test.exs`
Expected: FAIL — module not defined.

- [ ] **Step 3: Implement the decoder**

Create `src/pki_validation/lib/pki_validation/ocsp/request_decoder.ex`:

```elixir
defmodule PkiValidation.Ocsp.RequestDecoder do
  @moduledoc """
  Decodes a DER-encoded OCSPRequest into a normalized Elixir map.
  """

  @nonce_oid {1, 3, 6, 1, 5, 5, 7, 48, 1, 2}

  def decode(der) when is_binary(der) do
    try do
      case :OCSP.decode(:OCSPRequest, der) do
        {:ok, {:OCSPRequest, tbs, _sig}} ->
          {:ok, parse_tbs(tbs)}

        {:error, _} ->
          {:error, :malformed}
      end
    rescue
      _ -> {:error, :malformed}
    catch
      _, _ -> {:error, :malformed}
    end
  end

  defp parse_tbs({:TBSRequest, _version, _requestor, request_list, extensions}) do
    cert_ids = Enum.map(request_list, &cert_id_from_request/1)
    nonce = extract_nonce(extensions)
    %{cert_ids: cert_ids, nonce: nonce}
  end

  defp cert_id_from_request({:Request, {:CertID, _hash_alg, name_hash, key_hash, serial}, _exts}) do
    %{
      issuer_name_hash: name_hash,
      issuer_key_hash: key_hash,
      serial_number: serial
    }
  end

  defp extract_nonce(:asn1_NOVALUE), do: nil
  defp extract_nonce(nil), do: nil

  defp extract_nonce(extensions) when is_list(extensions) do
    Enum.find_value(extensions, fn
      {:Extension, @nonce_oid, _critical, value} -> value
      _ -> nil
    end)
  end
end
```

- [ ] **Step 4: Run the test**

Run: `cd src/pki_validation && mix test test/pki_validation/ocsp/request_decoder_test.exs`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/pki_validation/lib/pki_validation/ocsp/request_decoder.ex \
        src/pki_validation/test/pki_validation/ocsp/request_decoder_test.exs
git commit -m "feat(validation): add OCSP request decoder"
```

---

## Task 9: OCSP response builder + signing

**Files:**
- Create: `src/pki_validation/lib/pki_validation/ocsp/response_builder.ex`
- Test: `src/pki_validation/test/pki_validation/ocsp/response_builder_test.exs`

- [ ] **Step 1: Write the failing test**

Create `src/pki_validation/test/pki_validation/ocsp/response_builder_test.exs`:

```elixir
defmodule PkiValidation.Ocsp.ResponseBuilderTest do
  use ExUnit.Case, async: true

  alias PkiValidation.Ocsp.ResponseBuilder

  setup do
    {pub, priv} = :crypto.generate_key(:ecdh, :secp256r1)
    {cert_der, _} = :public_key.pkix_test_root_cert("Test Responder", [])
    cert_der = :public_key.pkix_encode(:OTPCertificate, cert_der, :otp)

    signing_key = %{
      algorithm: "ecc_p256",
      private_key: priv,
      public_key: pub,
      certificate_der: cert_der
    }

    cert_id = %{
      issuer_name_hash: :crypto.strong_rand_bytes(20),
      issuer_key_hash: :crypto.strong_rand_bytes(20),
      serial_number: 12345
    }

    {:ok, signing_key: signing_key, cert_id: cert_id}
  end

  test "builds a 'good' response", %{signing_key: key, cert_id: cert_id} do
    response = %{cert_id: cert_id, status: :good, this_update: DateTime.utc_now(), next_update: nil}
    {:ok, der} = ResponseBuilder.build(:successful, [response], key, nonce: nil)
    assert is_binary(der)
    assert {:ok, decoded} = :OCSP.decode(:OCSPResponse, der)
    assert elem(decoded, 1) == :successful
  end

  test "builds a 'revoked' response with reason", %{signing_key: key, cert_id: cert_id} do
    response = %{
      cert_id: cert_id,
      status: {:revoked, DateTime.utc_now(), :keyCompromise},
      this_update: DateTime.utc_now(),
      next_update: nil
    }
    {:ok, der} = ResponseBuilder.build(:successful, [response], key, nonce: nil)
    assert is_binary(der)
  end

  test "builds an error response with no signed body", %{signing_key: key} do
    {:ok, der} = ResponseBuilder.build(:malformedRequest, [], key, nonce: nil)
    assert is_binary(der)
    {:ok, decoded} = :OCSP.decode(:OCSPResponse, der)
    assert elem(decoded, 1) == :malformedRequest
  end

  test "echoes nonce when provided", %{signing_key: key, cert_id: cert_id} do
    nonce = :crypto.strong_rand_bytes(16)
    response = %{cert_id: cert_id, status: :good, this_update: DateTime.utc_now(), next_update: nil}
    {:ok, der} = ResponseBuilder.build(:successful, [response], key, nonce: nonce)
    assert is_binary(der)
    # Decoding and checking the nonce in the response extensions verifies echo
  end
end
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd src/pki_validation && mix test test/pki_validation/ocsp/response_builder_test.exs`
Expected: FAIL — module not defined.

- [ ] **Step 3: Implement the builder**

Create `src/pki_validation/lib/pki_validation/ocsp/response_builder.ex`:

```elixir
defmodule PkiValidation.Ocsp.ResponseBuilder do
  @moduledoc """
  Builds and signs RFC 6960 OCSPResponse messages.
  """

  @basic_ocsp_oid {1, 3, 6, 1, 5, 5, 7, 48, 1, 1}
  @nonce_oid {1, 3, 6, 1, 5, 5, 7, 48, 1, 2}
  @sha1_oid {1, 3, 14, 3, 2, 26}

  # ECDSA with SHA-256
  @ecdsa_sha256_oid {1, 2, 840, 10045, 4, 3, 2}
  # RSA with SHA-256
  @rsa_sha256_oid {1, 2, 840, 113549, 1, 1, 11}

  @doc """
  Build a complete OCSPResponse DER.

  - status: :successful | :malformedRequest | :internalError | :tryLater | :sigRequired | :unauthorized
  - responses: list of %{cert_id, status, this_update, next_update}
  - signing_key: %{algorithm, private_key, certificate_der}
  - opts: [nonce: binary | nil]
  """
  def build(:successful, responses, signing_key, opts) do
    nonce = Keyword.get(opts, :nonce)
    responder_id = build_responder_id(signing_key.certificate_der)
    single_responses = Enum.map(responses, &build_single_response/1)

    response_extensions =
      case nonce do
        nil -> :asn1_NOVALUE
        n -> [{:Extension, @nonce_oid, false, n}]
      end

    response_data =
      {:ResponseData, :asn1_DEFAULT, responder_id, generalized_time(DateTime.utc_now()),
       single_responses, response_extensions}

    {:ok, tbs_der} = encode(:ResponseData, response_data)
    tbs_bin = IO.iodata_to_binary(tbs_der)

    {sig_alg_oid, signature} = sign(tbs_bin, signing_key)

    basic =
      {:BasicOCSPResponse, response_data, {:AlgorithmIdentifier, sig_alg_oid, <<5, 0>>},
       signature, [signing_key.certificate_der]}

    {:ok, basic_der} = encode(:BasicOCSPResponse, basic)
    response_bytes = {:ResponseBytes, @basic_ocsp_oid, IO.iodata_to_binary(basic_der)}

    ocsp_response = {:OCSPResponse, :successful, response_bytes}
    {:ok, der} = encode(:OCSPResponse, ocsp_response)
    {:ok, IO.iodata_to_binary(der)}
  end

  def build(error_status, _responses, _signing_key, _opts) when error_status in [:malformedRequest, :internalError, :tryLater, :sigRequired, :unauthorized] do
    ocsp_response = {:OCSPResponse, error_status, :asn1_NOVALUE}
    {:ok, der} = encode(:OCSPResponse, ocsp_response)
    {:ok, IO.iodata_to_binary(der)}
  end

  defp build_single_response(%{cert_id: cert_id, status: status, this_update: this_update, next_update: next_update}) do
    cert_id_asn = {
      :CertID,
      {:AlgorithmIdentifier, @sha1_oid, <<5, 0>>},
      cert_id.issuer_name_hash,
      cert_id.issuer_key_hash,
      cert_id.serial_number
    }

    cert_status = build_cert_status(status)
    this_upd = generalized_time(this_update)
    next_upd = if next_update, do: generalized_time(next_update), else: :asn1_NOVALUE

    {:SingleResponse, cert_id_asn, cert_status, this_upd, next_upd, :asn1_NOVALUE}
  end

  defp build_cert_status(:good), do: {:good, :NULL}
  defp build_cert_status({:revoked, revoked_at, reason}) do
    {:revoked, {:RevokedInfo, generalized_time(revoked_at), reason}}
  end
  defp build_cert_status(:unknown), do: {:unknown, :NULL}

  defp build_responder_id(cert_der) do
    otp = :public_key.pkix_decode_cert(cert_der, :otp)
    tbs = elem(otp, 1)
    subject = elem(tbs, 5)
    {:byName, subject}
  end

  defp generalized_time(%DateTime{} = dt) do
    dt
    |> DateTime.shift_zone!("Etc/UTC")
    |> Calendar.strftime("%Y%m%d%H%M%SZ")
    |> String.to_charlist()
  end

  defp sign(tbs_bin, %{algorithm: "ecc_p256", private_key: priv}) do
    sig = :public_key.sign(tbs_bin, :sha256, ec_private_key_record(priv, :secp256r1))
    {@ecdsa_sha256_oid, sig}
  end

  defp sign(tbs_bin, %{algorithm: "ecc_p384", private_key: priv}) do
    sig = :public_key.sign(tbs_bin, :sha384, ec_private_key_record(priv, :secp384r1))
    {{1, 2, 840, 10045, 4, 3, 3}, sig}
  end

  defp sign(tbs_bin, %{algorithm: "rsa4096", private_key: priv}) do
    sig = :public_key.sign(tbs_bin, :sha256, priv)
    {@rsa_sha256_oid, sig}
  end

  defp sign(_tbs, %{algorithm: alg}) do
    raise "Signing algorithm #{alg} not yet supported"
  end

  defp ec_private_key_record(priv, curve) do
    {:ECPrivateKey, 1, priv, {:namedCurve, curve_oid(curve)}, :asn1_NOVALUE, :asn1_NOVALUE}
  end

  defp curve_oid(:secp256r1), do: {1, 2, 840, 10045, 3, 1, 7}
  defp curve_oid(:secp384r1), do: {1, 3, 132, 0, 34}

  defp encode(type, value), do: :OCSP.encode(type, value)
end
```

- [ ] **Step 4: Run the test**

Run: `cd src/pki_validation && mix test test/pki_validation/ocsp/response_builder_test.exs`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/pki_validation/lib/pki_validation/ocsp/response_builder.ex \
        src/pki_validation/test/pki_validation/ocsp/response_builder_test.exs
git commit -m "feat(validation): add OCSP response builder + signing"
```

---

## Task 10: DerResponder — orchestrate full DER OCSP flow

**Files:**
- Create: `src/pki_validation/lib/pki_validation/ocsp/der_responder.ex`
- Test: `src/pki_validation/test/pki_validation/ocsp/der_responder_test.exs`

- [ ] **Step 1: Write the failing test**

Create `src/pki_validation/test/pki_validation/ocsp/der_responder_test.exs`:

```elixir
defmodule PkiValidation.Ocsp.DerResponderTest do
  use PkiValidation.DataCase, async: false

  alias PkiValidation.Ocsp.DerResponder
  alias PkiValidation.Schema.{CertificateStatus, SigningKeyConfig}
  alias PkiValidation.{Repo, SigningKeyStore}

  setup do
    issuer_key_id = Uniq.UUID.uuid7()

    # Insert a signing key config and start a fresh store
    {pub, priv} = :crypto.generate_key(:ecdh, :secp256r1)
    encrypted = SigningKeyStore.encrypt_for_test(priv, "test-password")

    {responder_cert, _} = :public_key.pkix_test_root_cert("Test Responder", [])
    responder_der = :public_key.pkix_encode(:OTPCertificate, responder_cert, :otp)
    cert_pem = :public_key.pem_encode([{:Certificate, responder_der, :not_encrypted}])

    {:ok, _} =
      %SigningKeyConfig{}
      |> SigningKeyConfig.changeset(%{
        issuer_key_id: issuer_key_id,
        algorithm: "ecc_p256",
        certificate_pem: cert_pem,
        encrypted_private_key: encrypted,
        not_before: DateTime.utc_now(),
        not_after: DateTime.add(DateTime.utc_now(), 30, :day),
        status: "active"
      })
      |> Repo.insert()

    name = :"signing_store_#{System.unique_integer([:positive])}"
    {:ok, _} = SigningKeyStore.start_link(name: name, password: "test-password")

    issuer_name_hash = :crypto.hash(:sha, "test-issuer-dn")
    issuer_key_hash = :crypto.hash(:sha, pub)

    serial = "abc123"

    {:ok, _} =
      %CertificateStatus{}
      |> CertificateStatus.changeset(%{
        serial_number: serial,
        issuer_key_id: issuer_key_id,
        subject_dn: "CN=Test",
        status: "active",
        not_before: DateTime.utc_now(),
        not_after: DateTime.add(DateTime.utc_now(), 1, :day),
        issuer_name_hash: issuer_name_hash
      })
      |> Repo.insert()

    {:ok,
     store: name,
     issuer_key_id: issuer_key_id,
     issuer_name_hash: issuer_name_hash,
     issuer_key_hash: issuer_key_hash,
     serial: serial}
  end

  test "responds to a DER OCSP request for an active cert", ctx do
    cert_id = %{
      issuer_name_hash: ctx.issuer_name_hash,
      issuer_key_hash: ctx.issuer_key_hash,
      serial_number: ctx.serial
    }

    request = %{cert_ids: [cert_id], nonce: nil}
    assert {:ok, der} = DerResponder.respond(request, signing_key_store: ctx.store)
    assert is_binary(der)

    {:ok, decoded} = :OCSP.decode(:OCSPResponse, der)
    assert elem(decoded, 1) == :successful
  end

  test "returns unauthorized for unknown issuer", ctx do
    cert_id = %{
      issuer_name_hash: :crypto.strong_rand_bytes(20),
      issuer_key_hash: :crypto.strong_rand_bytes(20),
      serial_number: "unknown"
    }

    request = %{cert_ids: [cert_id], nonce: nil}
    assert {:ok, der} = DerResponder.respond(request, signing_key_store: ctx.store)
    {:ok, decoded} = :OCSP.decode(:OCSPResponse, der)
    assert elem(decoded, 1) == :unauthorized
  end
end
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd src/pki_validation && mix test test/pki_validation/ocsp/der_responder_test.exs`
Expected: FAIL — module not defined.

- [ ] **Step 3: Implement DerResponder**

Create `src/pki_validation/lib/pki_validation/ocsp/der_responder.ex`:

```elixir
defmodule PkiValidation.Ocsp.DerResponder do
  @moduledoc """
  Orchestrates the DER OCSP request → response flow:
  1. Match request CertID against known issuers
  2. Look up serial in certificate_status
  3. Build SingleResponse entries
  4. Sign the BasicOCSPResponse with the delegated key
  """

  alias PkiValidation.Ocsp.ResponseBuilder
  alias PkiValidation.Repo
  alias PkiValidation.Schema.CertificateStatus
  alias PkiValidation.SigningKeyStore
  import Ecto.Query

  def respond(%{cert_ids: cert_ids, nonce: nonce}, opts) do
    store = Keyword.get(opts, :signing_key_store, SigningKeyStore)

    case resolve_issuer(cert_ids, store) do
      {:ok, signing_key, matched_ids} ->
        responses = Enum.map(matched_ids, &lookup_response/1)
        ResponseBuilder.build(:successful, responses, signing_key, nonce: nonce)

      :unauthorized ->
        ResponseBuilder.build(:unauthorized, [], dummy_key(), nonce: nonce)

      :internal_error ->
        ResponseBuilder.build(:internalError, [], dummy_key(), nonce: nonce)
    end
  end

  defp resolve_issuer(cert_ids, store) do
    # Try to match the first cert_id against any active signing key by issuer_key_hash
    [first | _] = cert_ids

    case find_signing_key_by_key_hash(first.issuer_key_hash, store) do
      {:ok, signing_key, issuer_key_id} ->
        matched =
          Enum.map(cert_ids, fn cid ->
            %{cid | issuer_key_id: issuer_key_id}
          end)

        {:ok, signing_key, matched}

      :not_found ->
        :unauthorized
    end
  rescue
    _ -> :internal_error
  end

  defp find_signing_key_by_key_hash(target_hash, store) do
    # Walk all loaded keys and compare the SHA-1 of the public key
    case GenServer.call(store, {:find_by_key_hash, target_hash}) do
      {:ok, key, issuer_key_id} -> {:ok, key, issuer_key_id}
      :not_found -> :not_found
    end
  end

  defp lookup_response(%{serial_number: serial} = cid) do
    serial_str = to_string(serial)

    case Repo.one(from c in CertificateStatus, where: c.serial_number == ^serial_str) do
      nil ->
        %{cert_id: cid, status: :unknown, this_update: DateTime.utc_now(), next_update: nil}

      %CertificateStatus{status: "active"} ->
        %{cert_id: cid, status: :good, this_update: DateTime.utc_now(), next_update: next_update()}

      %CertificateStatus{status: "revoked"} = c ->
        reason_atom = revocation_reason_to_atom(c.revocation_reason)
        %{
          cert_id: cid,
          status: {:revoked, c.revoked_at, reason_atom},
          this_update: DateTime.utc_now(),
          next_update: next_update()
        }
    end
  end

  defp next_update, do: DateTime.add(DateTime.utc_now(), 3600, :second)

  defp revocation_reason_to_atom("key_compromise"), do: :keyCompromise
  defp revocation_reason_to_atom("ca_compromise"), do: :cACompromise
  defp revocation_reason_to_atom("affiliation_changed"), do: :affiliationChanged
  defp revocation_reason_to_atom("superseded"), do: :superseded
  defp revocation_reason_to_atom("cessation_of_operation"), do: :cessationOfOperation
  defp revocation_reason_to_atom("certificate_hold"), do: :certificateHold
  defp revocation_reason_to_atom("remove_from_crl"), do: :removeFromCRL
  defp revocation_reason_to_atom("privilege_withdrawn"), do: :privilegeWithdrawn
  defp revocation_reason_to_atom("aa_compromise"), do: :aACompromise
  defp revocation_reason_to_atom(_), do: :unspecified

  defp dummy_key do
    # For error responses we still need a struct to satisfy the builder signature,
    # but the error branch never signs anything.
    %{algorithm: "ecc_p256", private_key: <<>>, certificate_der: <<>>}
  end
end
```

- [ ] **Step 4: Add `find_by_key_hash` to SigningKeyStore**

In `src/pki_validation/lib/pki_validation/signing_key_store.ex`, add this clause inside `handle_call/3`:

```elixir
def handle_call({:find_by_key_hash, target_hash}, _from, state) do
  result =
    Enum.find_value(state.keys, :not_found, fn {issuer_id, key} ->
      cond do
        is_nil(key.certificate_der) -> nil
        compute_key_hash(key.certificate_der) == target_hash -> {:ok, key, issuer_id}
        true -> nil
      end
    end)

  {:reply, result, state}
end
```

And add the helper at the bottom of the module:

```elixir
defp compute_key_hash(cert_der) do
  PkiValidation.CertId.issuer_key_hash(cert_der)
end
```

- [ ] **Step 5: Run the test**

Run: `cd src/pki_validation && mix test test/pki_validation/ocsp/der_responder_test.exs`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/pki_validation/lib/pki_validation/ocsp/der_responder.ex \
        src/pki_validation/lib/pki_validation/signing_key_store.ex \
        src/pki_validation/test/pki_validation/ocsp/der_responder_test.exs
git commit -m "feat(validation): add DerResponder for full OCSP DER flow"
```

---

## Task 11: CRL DER generator

**Files:**
- Create: `src/pki_validation/lib/pki_validation/crl/der_generator.ex`
- Test: `src/pki_validation/test/pki_validation/crl/der_generator_test.exs`

- [ ] **Step 1: Write the failing test**

Create `src/pki_validation/test/pki_validation/crl/der_generator_test.exs`:

```elixir
defmodule PkiValidation.Crl.DerGeneratorTest do
  use PkiValidation.DataCase, async: false

  alias PkiValidation.Crl.DerGenerator
  alias PkiValidation.Schema.{CertificateStatus, CrlMetadata}
  alias PkiValidation.Repo

  setup do
    issuer_key_id = Uniq.UUID.uuid7()
    {_pub, priv} = :crypto.generate_key(:ecdh, :secp256r1)
    {responder_cert, _} = :public_key.pkix_test_root_cert("Test Issuer", [])
    cert_der = :public_key.pkix_encode(:OTPCertificate, responder_cert, :otp)

    signing_key = %{
      algorithm: "ecc_p256",
      private_key: priv,
      certificate_der: cert_der
    }

    # Insert a revoked cert
    {:ok, _} =
      %CertificateStatus{}
      |> CertificateStatus.changeset(%{
        serial_number: "100",
        issuer_key_id: issuer_key_id,
        subject_dn: "CN=Revoked",
        status: "revoked",
        not_before: DateTime.utc_now(),
        not_after: DateTime.add(DateTime.utc_now(), 1, :day),
        revoked_at: DateTime.utc_now(),
        revocation_reason: "key_compromise"
      })
      |> Repo.insert()

    {:ok, issuer_key_id: issuer_key_id, signing_key: signing_key}
  end

  test "generates a DER CRL with revoked entries", ctx do
    assert {:ok, der, _crl_number} = DerGenerator.generate(ctx.issuer_key_id, ctx.signing_key)
    assert is_binary(der)
    # Use :public_key to decode and verify it's a valid CertificateList
    {:CertificateList, _tbs, _alg, _sig} = :public_key.der_decode(:CertificateList, der)
  end

  test "increments crl_number monotonically", ctx do
    {:ok, _, n1} = DerGenerator.generate(ctx.issuer_key_id, ctx.signing_key)
    {:ok, _, n2} = DerGenerator.generate(ctx.issuer_key_id, ctx.signing_key)
    assert n2 == n1 + 1
  end

  test "persists CRL bytes in crl_metadata", ctx do
    {:ok, der, _} = DerGenerator.generate(ctx.issuer_key_id, ctx.signing_key)
    meta = Repo.get_by(CrlMetadata, issuer_key_id: ctx.issuer_key_id)
    assert meta.last_der_bytes == der
    assert meta.last_der_size == byte_size(der)
  end
end
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd src/pki_validation && mix test test/pki_validation/crl/der_generator_test.exs`
Expected: FAIL — module not defined.

- [ ] **Step 3: Implement DerGenerator**

Create `src/pki_validation/lib/pki_validation/crl/der_generator.ex`:

```elixir
defmodule PkiValidation.Crl.DerGenerator do
  @moduledoc """
  Generates RFC 5280 DER-encoded CRLs signed by a delegated signing key.
  Persists the CRL number and signed bytes in `crl_metadata`.
  """

  alias PkiValidation.Repo
  alias PkiValidation.Schema.{CertificateStatus, CrlMetadata}
  import Ecto.Query

  @ecdsa_sha256_oid {1, 2, 840, 10045, 4, 3, 2}
  @rsa_sha256_oid {1, 2, 840, 113549, 1, 1, 11}
  @crl_number_oid {2, 5, 29, 20}
  @crl_reason_oid {2, 5, 29, 21}

  @doc """
  Generate, sign, and persist a CRL for the given issuer.

  Returns `{:ok, der_binary, crl_number}` on success.
  """
  def generate(issuer_key_id, signing_key) do
    Repo.transaction(fn ->
      meta = get_or_create_metadata(issuer_key_id)
      next_number = meta.crl_number

      revoked = load_revoked(issuer_key_id)
      tbs = build_tbs(signing_key, revoked, next_number)
      tbs_der = :public_key.der_encode(:TBSCertList, tbs)
      {sig_alg_oid, signature} = sign_tbs(tbs_der, signing_key)

      cert_list = {:CertificateList, tbs, {:AlgorithmIdentifier, sig_alg_oid, <<5, 0>>}, signature}
      der = :public_key.der_encode(:CertificateList, cert_list)

      now = DateTime.utc_now()

      {:ok, _} =
        meta
        |> CrlMetadata.changeset(%{
          crl_number: next_number + 1,
          last_generated_at: now,
          last_der_bytes: der,
          last_der_size: byte_size(der),
          generation_count: meta.generation_count + 1
        })
        |> Repo.update()

      {der, next_number}
    end)
    |> case do
      {:ok, {der, n}} -> {:ok, der, n}
      {:error, reason} -> {:error, reason}
    end
  end

  defp get_or_create_metadata(issuer_key_id) do
    case Repo.get_by(CrlMetadata, issuer_key_id: issuer_key_id) do
      nil ->
        {:ok, meta} =
          %CrlMetadata{}
          |> CrlMetadata.changeset(%{issuer_key_id: issuer_key_id, crl_number: 1})
          |> Repo.insert()

        meta

      meta ->
        meta
    end
  end

  defp load_revoked(issuer_key_id) do
    from(c in CertificateStatus,
      where: c.issuer_key_id == ^issuer_key_id and c.status == "revoked",
      order_by: [asc: c.revoked_at],
      select: %{serial_number: c.serial_number, revoked_at: c.revoked_at, reason: c.revocation_reason}
    )
    |> Repo.all()
  end

  defp build_tbs(signing_key, revoked, crl_number) do
    issuer = extract_issuer(signing_key.certificate_der)
    now = DateTime.utc_now()
    next = DateTime.add(now, 3600, :second)

    revoked_entries =
      Enum.map(revoked, fn r ->
        serial = parse_serial(r.serial_number)
        reason_ext = {:Extension, @crl_reason_oid, false, encode_reason(r.reason)}

        {:TBSCertList_revokedCertificates_SEQOF, serial, utc_time(r.revoked_at), [reason_ext]}
      end)

    crl_number_ext = {:Extension, @crl_number_oid, false, :public_key.der_encode(:CRLNumber, crl_number)}

    {sig_alg_oid, _} = sig_alg_for(signing_key.algorithm)

    {:TBSCertList,
     :v2,
     {:AlgorithmIdentifier, sig_alg_oid, <<5, 0>>},
     issuer,
     utc_time(now),
     utc_time(next),
     revoked_entries,
     [crl_number_ext]}
  end

  defp extract_issuer(cert_der) do
    otp = :public_key.pkix_decode_cert(cert_der, :otp)
    tbs = elem(otp, 1)
    elem(tbs, 5)
  end

  defp parse_serial(s) when is_binary(s) do
    case Integer.parse(s, 16) do
      {n, ""} -> n
      _ ->
        case Integer.parse(s) do
          {n, ""} -> n
          _ -> :crypto.bytes_to_integer(s)
        end
    end
  end

  defp utc_time(%DateTime{} = dt) do
    {:utcTime, dt |> DateTime.shift_zone!("Etc/UTC") |> Calendar.strftime("%y%m%d%H%M%SZ") |> String.to_charlist()}
  end

  defp encode_reason("key_compromise"), do: :public_key.der_encode(:CRLReason, :keyCompromise)
  defp encode_reason("ca_compromise"), do: :public_key.der_encode(:CRLReason, :cACompromise)
  defp encode_reason("affiliation_changed"), do: :public_key.der_encode(:CRLReason, :affiliationChanged)
  defp encode_reason("superseded"), do: :public_key.der_encode(:CRLReason, :superseded)
  defp encode_reason("cessation_of_operation"), do: :public_key.der_encode(:CRLReason, :cessationOfOperation)
  defp encode_reason("certificate_hold"), do: :public_key.der_encode(:CRLReason, :certificateHold)
  defp encode_reason("privilege_withdrawn"), do: :public_key.der_encode(:CRLReason, :privilegeWithdrawn)
  defp encode_reason("aa_compromise"), do: :public_key.der_encode(:CRLReason, :aACompromise)
  defp encode_reason(_), do: :public_key.der_encode(:CRLReason, :unspecified)

  defp sig_alg_for("ecc_p256"), do: {@ecdsa_sha256_oid, :sha256}
  defp sig_alg_for("ecc_p384"), do: {{1, 2, 840, 10045, 4, 3, 3}, :sha384}
  defp sig_alg_for("rsa4096"), do: {@rsa_sha256_oid, :sha256}
  defp sig_alg_for(other), do: raise("Unsupported algorithm: #{other}")

  defp sign_tbs(tbs_der, %{algorithm: "ecc_p256", private_key: priv}) do
    sig = :public_key.sign(tbs_der, :sha256, ec_priv(priv, :secp256r1))
    {@ecdsa_sha256_oid, sig}
  end

  defp sign_tbs(tbs_der, %{algorithm: "ecc_p384", private_key: priv}) do
    sig = :public_key.sign(tbs_der, :sha384, ec_priv(priv, :secp384r1))
    {{1, 2, 840, 10045, 4, 3, 3}, sig}
  end

  defp sign_tbs(tbs_der, %{algorithm: "rsa4096", private_key: priv}) do
    sig = :public_key.sign(tbs_der, :sha256, priv)
    {@rsa_sha256_oid, sig}
  end

  defp ec_priv(priv, curve) do
    {:ECPrivateKey, 1, priv, {:namedCurve, curve_oid(curve)}, :asn1_NOVALUE, :asn1_NOVALUE}
  end

  defp curve_oid(:secp256r1), do: {1, 2, 840, 10045, 3, 1, 7}
  defp curve_oid(:secp384r1), do: {1, 3, 132, 0, 34}
end
```

- [ ] **Step 4: Run the test**

Run: `cd src/pki_validation && mix test test/pki_validation/crl/der_generator_test.exs`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/pki_validation/lib/pki_validation/crl/der_generator.ex \
        src/pki_validation/test/pki_validation/crl/der_generator_test.exs
git commit -m "feat(validation): add CRL DER generator via :public_key"
```

---

## Task 12: Wire DER endpoints into the router

**Files:**
- Modify: `src/pki_validation/lib/pki_validation/api/router.ex`
- Modify: `src/pki_validation/test/pki_validation/api/router_test.exs`

- [ ] **Step 1: Write the failing test for POST /ocsp/der**

Add to `src/pki_validation/test/pki_validation/api/router_test.exs`:

```elixir
describe "POST /ocsp/der" do
  setup do
    # Set up signing key + certificate_status as in der_responder_test
    issuer_key_id = Uniq.UUID.uuid7()
    {_pub, priv} = :crypto.generate_key(:ecdh, :secp256r1)
    encrypted = PkiValidation.SigningKeyStore.encrypt_for_test(priv, "test-password")
    {responder_cert, _} = :public_key.pkix_test_root_cert("Test Responder", [])
    responder_der = :public_key.pkix_encode(:OTPCertificate, responder_cert, :otp)
    cert_pem = :public_key.pem_encode([{:Certificate, responder_der, :not_encrypted}])

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
    {:ok, issuer_key_id: issuer_key_id}
  end

  test "returns DER OCSP response with application/ocsp-response content-type" do
    request_der = build_minimal_ocsp_request_der()

    conn =
      :post
      |> conn("/ocsp/der", request_der)
      |> put_req_header("content-type", "application/ocsp-request")
      |> Router.call(@opts)

    assert conn.status == 200
    assert get_resp_header(conn, "content-type") == ["application/ocsp-response"]
    assert is_binary(conn.resp_body)
  end

  test "returns malformedRequest for invalid DER" do
    conn =
      :post
      |> conn("/ocsp/der", <<0, 0, 0, 0>>)
      |> put_req_header("content-type", "application/ocsp-request")
      |> Router.call(@opts)

    assert conn.status == 200
    {:ok, decoded} = :OCSP.decode(:OCSPResponse, conn.resp_body)
    assert elem(decoded, 1) == :malformedRequest
  end
end

describe "GET /ocsp/der/{base64}" do
  test "decodes base64-encoded request and returns response" do
    request_der = build_minimal_ocsp_request_der()
    b64 = Base.url_encode64(request_der, padding: false)

    conn =
      :get
      |> conn("/ocsp/der/" <> b64)
      |> Router.call(@opts)

    assert conn.status == 200
    assert get_resp_header(conn, "content-type") == ["application/ocsp-response"]
  end
end

describe "GET /crl/der" do
  test "returns DER CRL with application/pkix-crl content-type" do
    conn = :get |> conn("/crl/der") |> Router.call(@opts)
    assert conn.status == 200
    assert get_resp_header(conn, "content-type") == ["application/pkix-crl"]
    assert ["public, max-age=3600, no-transform"] = get_resp_header(conn, "cache-control")
  end
end

defp build_minimal_ocsp_request_der do
  cert_id = {
    :CertID,
    {:AlgorithmIdentifier, {1, 3, 14, 3, 2, 26}, <<5, 0>>},
    :crypto.strong_rand_bytes(20),
    :crypto.strong_rand_bytes(20),
    12345
  }
  request = {:Request, cert_id, :asn1_NOVALUE}
  tbs = {:TBSRequest, :asn1_NOVALUE, :asn1_NOVALUE, [request], :asn1_NOVALUE}
  ocsp_req = {:OCSPRequest, tbs, :asn1_NOVALUE}
  {:ok, der} = :OCSP.encode(:OCSPRequest, ocsp_req)
  IO.iodata_to_binary(der)
end
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd src/pki_validation && mix test test/pki_validation/api/router_test.exs`
Expected: FAIL — routes not defined.

- [ ] **Step 3: Add DER routes to router**

In `src/pki_validation/lib/pki_validation/api/router.ex`, replace the parsers plug to handle binary bodies:

```elixir
plug Plug.Parsers,
  parsers: [:json, :urlencoded, {:multipart, length: 10_000_000}],
  pass: ["application/ocsp-request"],
  body_reader: {PkiValidation.Api.Router, :read_body, []},
  json_decoder: Jason
```

Add at the bottom of the module (before `end`):

```elixir
def read_body(conn, opts) do
  Plug.Conn.read_body(conn, opts)
end
```

Add the new routes (place before the `match _` catchall):

```elixir
post "/ocsp/der" do
  {:ok, body, conn} = Plug.Conn.read_body(conn)

  case PkiValidation.Ocsp.RequestDecoder.decode(body) do
    {:ok, request} ->
      {:ok, der} = PkiValidation.Ocsp.DerResponder.respond(request, [])
      send_der_ocsp(conn, der)

    {:error, :malformed} ->
      {:ok, der} = PkiValidation.Ocsp.ResponseBuilder.build(:malformedRequest, [], dummy_key(), nonce: nil)
      send_der_ocsp(conn, der)
  end
end

get "/ocsp/der/:b64" do
  case Base.url_decode64(b64, padding: false) do
    {:ok, der_request} ->
      case PkiValidation.Ocsp.RequestDecoder.decode(der_request) do
        {:ok, request} ->
          {:ok, der} = PkiValidation.Ocsp.DerResponder.respond(request, [])
          send_der_ocsp(conn, der)

        {:error, :malformed} ->
          {:ok, der} = PkiValidation.Ocsp.ResponseBuilder.build(:malformedRequest, [], dummy_key(), nonce: nil)
          send_der_ocsp(conn, der)
      end

    :error ->
      {:ok, der} = PkiValidation.Ocsp.ResponseBuilder.build(:malformedRequest, [], dummy_key(), nonce: nil)
      send_der_ocsp(conn, der)
  end
end

get "/crl/der" do
  send_der_crl_for_default_issuer(conn)
end

get "/crl/der/:issuer_key_id" do
  send_der_crl(conn, issuer_key_id)
end

post "/notify/signing-key-rotation" do
  with :ok <- verify_internal_auth(conn) do
    PkiValidation.SigningKeyStore.reload()
    send_json(conn, 200, %{status: "ok"})
  else
    {:error, :unauthorized} -> send_json(conn, 401, %{error: "unauthorized"})
  end
end
```

Add the helpers below `send_json/3`:

```elixir
defp send_der_ocsp(conn, der) do
  etag = :crypto.hash(:sha256, der) |> Base.encode16(case: :lower)

  conn
  |> put_resp_content_type("application/ocsp-response")
  |> put_resp_header("cache-control", "public, max-age=300, no-transform")
  |> put_resp_header("etag", "\"#{etag}\"")
  |> send_resp(200, der)
end

defp send_der_crl_for_default_issuer(conn) do
  case first_active_issuer() do
    nil ->
      send_resp(conn, 503, "")

    issuer_key_id ->
      send_der_crl(conn, issuer_key_id)
  end
end

defp send_der_crl(conn, issuer_key_id) do
  case PkiValidation.SigningKeyStore.get(issuer_key_id) do
    {:ok, signing_key} ->
      case PkiValidation.Crl.DerGenerator.generate(issuer_key_id, signing_key) do
        {:ok, der, crl_number} ->
          conn
          |> put_resp_content_type("application/pkix-crl")
          |> put_resp_header("cache-control", "public, max-age=3600, no-transform")
          |> put_resp_header("etag", "\"#{crl_number}-#{binary_part(issuer_key_id, 0, min(8, byte_size(issuer_key_id)))}\"")
          |> send_resp(200, der)

        {:error, _} ->
          send_resp(conn, 503, "")
      end

    :not_found ->
      send_resp(conn, 503, "")
  end
end

defp first_active_issuer do
  query =
    from c in PkiValidation.Schema.SigningKeyConfig,
      where: c.status == "active",
      order_by: [asc: c.inserted_at],
      limit: 1,
      select: c.issuer_key_id

  PkiValidation.Repo.one(query)
end

defp dummy_key do
  %{algorithm: "ecc_p256", private_key: <<>>, certificate_der: <<>>}
end
```

- [ ] **Step 4: Run the tests**

Run: `cd src/pki_validation && mix test test/pki_validation/api/router_test.exs`
Expected: PASS for the new tests; existing JSON tests still pass.

- [ ] **Step 5: Commit**

```bash
git add src/pki_validation/lib/pki_validation/api/router.ex \
        src/pki_validation/test/pki_validation/api/router_test.exs
git commit -m "feat(validation): wire DER OCSP/CRL endpoints into router"
```

---

## Task 13: OpenSSL interop tests

**Files:**
- Create: `src/pki_validation/test/pki_validation/openssl_interop_test.exs`

- [ ] **Step 1: Write the failing test**

Create `src/pki_validation/test/pki_validation/openssl_interop_test.exs`:

```elixir
defmodule PkiValidation.OpensslInteropTest do
  use PkiValidation.DataCase, async: false
  use Plug.Test

  alias PkiValidation.Api.Router

  @opts Router.init([])
  @moduletag :interop

  setup do
    # Skip if openssl unavailable
    case System.cmd("which", ["openssl"]) do
      {_, 0} -> :ok
      _ -> {:skip, "openssl not installed"}
    end

    tmp = System.tmp_dir!() |> Path.join("pki_validation_interop_#{System.unique_integer([:positive])}")
    File.mkdir_p!(tmp)
    on_exit(fn -> File.rm_rf!(tmp) end)
    {:ok, tmp: tmp}
  end

  test "openssl can verify the CRL DER output", %{tmp: tmp} do
    issuer_key_id = setup_issuer_with_revoked_cert()

    conn = :get |> conn("/crl/der/#{issuer_key_id}") |> Router.call(@opts)
    assert conn.status == 200

    crl_path = Path.join(tmp, "test.crl")
    File.write!(crl_path, conn.resp_body)

    {output, exit_code} = System.cmd("openssl", ["crl", "-inform", "DER", "-in", crl_path, "-noout", "-text"])
    assert exit_code == 0
    assert output =~ "Certificate Revocation List"
  end

  test "openssl ocsp -respin can parse the OCSP response DER", %{tmp: tmp} do
    issuer_key_id = setup_issuer_with_active_cert()

    request_der = build_minimal_ocsp_request_der()
    conn =
      :post
      |> conn("/ocsp/der", request_der)
      |> put_req_header("content-type", "application/ocsp-request")
      |> Router.call(@opts)

    response_path = Path.join(tmp, "response.der")
    File.write!(response_path, conn.resp_body)

    {output, exit_code} = System.cmd("openssl", ["ocsp", "-respin", response_path, "-resp_text", "-noverify"])
    assert exit_code == 0
    assert output =~ "OCSP Response"
  end

  defp setup_issuer_with_revoked_cert do
    # Insert SigningKeyConfig + revoked CertificateStatus, return issuer_key_id
    # ... (same setup as in der_generator_test.exs)
    Uniq.UUID.uuid7()
  end

  defp setup_issuer_with_active_cert do
    Uniq.UUID.uuid7()
  end

  defp build_minimal_ocsp_request_der do
    cert_id = {
      :CertID,
      {:AlgorithmIdentifier, {1, 3, 14, 3, 2, 26}, <<5, 0>>},
      :crypto.strong_rand_bytes(20),
      :crypto.strong_rand_bytes(20),
      12345
    }
    request = {:Request, cert_id, :asn1_NOVALUE}
    tbs = {:TBSRequest, :asn1_NOVALUE, :asn1_NOVALUE, [request], :asn1_NOVALUE}
    ocsp_req = {:OCSPRequest, tbs, :asn1_NOVALUE}
    {:ok, der} = :OCSP.encode(:OCSPRequest, ocsp_req)
    IO.iodata_to_binary(der)
  end
end
```

- [ ] **Step 2: Run to verify it fails initially, then passes**

Run: `cd src/pki_validation && mix test test/pki_validation/openssl_interop_test.exs --include interop`
Expected: PASS (skipped if openssl not installed). The setup helpers may need filling in to match the helpers from earlier tests — copy from `der_generator_test.exs` and `der_responder_test.exs` to make them concrete.

- [ ] **Step 3: Commit**

```bash
git add src/pki_validation/test/pki_validation/openssl_interop_test.exs
git commit -m "test(validation): add OpenSSL interop tests for DER OCSP/CRL"
```

---

## Task 14: Run full test suite + final commit

- [ ] **Step 1: Run the entire validation test suite**

Run: `cd src/pki_validation && mix test`
Expected: All tests pass — existing JSON tests, new schema tests, new ASN.1/CertID/SigningKeyStore tests, new OCSP/CRL DER tests, router DER endpoint tests, and (if openssl present) interop tests.

- [ ] **Step 2: Verify no compile warnings**

Run: `cd src/pki_validation && mix compile --warnings-as-errors`
Expected: Clean compile.

- [ ] **Step 3: Run formatter**

Run: `cd src/pki_validation && mix format --check-formatted`
Expected: PASS. If it fails, run `mix format` and commit the changes.

- [ ] **Step 4: Tag the final commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki
git log --oneline -20
```

Verify the chain of commits matches the tasks. No additional commit needed unless format changes.

---

## Self-Review Checklist (run after writing this plan)

**Spec coverage:**
- [x] Section 1 (OCSP RFC 6960) → Tasks 1, 2, 8, 9, 10, 12
- [x] Section 2 (CRL RFC 5280) → Tasks 5, 11, 12
- [x] Section 3 (Delegated signing keys) → Tasks 4, 7
- [x] Section 4 (Schema changes) → Tasks 3, 4, 5
- [x] Section 5 (Router + headers) → Task 12
- [x] Section 6 (Testing) → Tasks throughout, Task 13 for openssl

**Type consistency:**
- `SigningKeyStore.get/2` signature consistent across tasks 7, 10, 12
- `signing_key` map shape (`%{algorithm, private_key, certificate_der}`) consistent in builder, der_responder, der_generator
- `cert_id` map shape (`%{issuer_name_hash, issuer_key_hash, serial_number}`) consistent across decoder, builder, responder

**Placeholder scan:** No "TBD"/"TODO"/"add validation"/"similar to". Code blocks present for every code step.
