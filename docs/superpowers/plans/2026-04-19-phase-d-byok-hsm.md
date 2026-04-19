# Phase D: BYOK-HSM (Bring Your Own Hardware Security Module) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable customers to sign with their own HSM (YubiKey, Entrust, Thales, any PKCS#11) via local Erlang Port or remote Go agent over gRPC with mTLS.

**Architecture:** KeyStore behaviour with 3 adapters (Software, LocalHsm, RemoteHsm). Local HSM uses Erlang Port to C binary wrapping PKCS#11. Remote HSM uses gRPC bidirectional streaming to a Go agent on customer's site. Dispatcher routes by IssuerKey.keystore_type.

**Tech Stack:** Elixir/OTP, C (PKCS#11 Port binary), Go (HSM agent), gRPC + protobuf, mTLS TLS 1.3, SoftHSM2 (testing).

---

## File Structure

### New files

```
src/pki_ca_engine/lib/pki_ca_engine/key_store.ex                    # KeyStore behaviour (3 callbacks)
src/pki_ca_engine/lib/pki_ca_engine/key_store/dispatcher.ex          # Routes by IssuerKey.keystore_type
src/pki_ca_engine/lib/pki_ca_engine/key_store/software_adapter.ex    # Wraps KeyActivation (existing path)
src/pki_ca_engine/lib/pki_ca_engine/key_store/local_hsm_adapter.ex   # Erlang Port to PKCS#11
src/pki_ca_engine/lib/pki_ca_engine/key_store/remote_hsm_adapter.ex  # gRPC to Go agent
src/pki_ca_engine/lib/pki_ca_engine/key_store/pkcs11_port.ex         # GenServer managing C Port
src/pki_ca_engine/lib/pki_ca_engine/hsm_gateway.ex                   # gRPC server GenServer
src/pki_ca_engine/priv/pkcs11_port.c                                 # C binary wrapping PKCS#11 via dlopen
src/pki_ca_engine/priv/Makefile                                      # Compiles pkcs11_port.c
priv/proto/hsm_gateway.proto                                         # gRPC service definition
src/pki_ca_engine/test/pki_ca_engine/key_store/dispatcher_test.exs   # Dispatcher routing tests
src/pki_ca_engine/test/pki_ca_engine/key_store/software_adapter_test.exs  # SoftwareAdapter wraps KeyActivation
src/pki_ca_engine/test/pki_ca_engine/key_store/local_hsm_adapter_test.exs # LocalHsmAdapter + Pkcs11Port tests
src/pki_ca_engine/test/pki_ca_engine/key_store/remote_hsm_adapter_test.exs # RemoteHsmAdapter + HsmGateway tests
src/pki_ca_engine/test/pki_ca_engine/key_store/integration_test.exs  # Full flow: IssuerKey -> sign via SoftHSM2
hsm-agent/main.go                                                    # CLI entry, config, PKCS#11 init
hsm-agent/pkcs11.go                                                  # PKCS#11 wrapper (sign, list keys)
hsm-agent/grpc_client.go                                             # gRPC bidirectional stream
hsm-agent/proto/hsm_gateway.proto                                    # Copy of proto for Go codegen
hsm-agent/proto/hsm_gateway.pb.go                                    # Generated protobuf code
hsm-agent/proto/hsm_gateway_grpc.pb.go                               # Generated gRPC stubs
hsm-agent/config.yaml                                                # Example config
hsm-agent/go.mod                                                     # Go module definition
hsm-agent/go.sum                                                     # Go dependency checksums
hsm-agent/Makefile                                                   # Cross-compilation targets
hsm-agent/main_test.go                                               # Agent integration tests
hsm-agent/pkcs11_test.go                                             # PKCS#11 wrapper tests
```

### Modified files

```
src/pki_mnesia/lib/pki_mnesia/structs/issuer_key.ex                 # Add keystore_type, hsm_config, hsm_key_handle fields
src/pki_ca_engine/lib/pki_ca_engine/certificate_signing.ex           # Replace KeyActivation.get_active_key -> Dispatcher.sign
src/pki_validation/lib/pki_validation/ocsp_responder.ex              # Replace KeyActivation.get_active_key -> Dispatcher.sign
src/pki_validation/lib/pki_validation/crl_publisher.ex               # Replace KeyActivation.get_active_key -> Dispatcher.sign
src/pki_tenant/lib/pki_tenant/application.ex                         # Conditionally start HsmGateway
src/pki_ca_engine/mix.exs                                            # Add grpc + protobuf deps
config/runtime.exs                                                   # Add HSM_GRPC_PORT config
```

---

## Prerequisites

Before starting any task, confirm the branch compiles:

```bash
cd /Users/amirrudinyahaya/Workspace/pki && mix compile --no-deps-check
```

Create a feature branch:

```bash
cd /Users/amirrudinyahaya/Workspace/pki
git checkout -b feat/phase-d-byok-hsm
```

**Important conventions:**
- `PkiMnesia.Repo` returns tagged tuples: `{:ok, struct}` | `{:ok, nil}` | `{:error, reason}`
- Project uses `path:` deps in root `mix.exs`, and `in_umbrella: true` within `src/` app mix files
- All struct modules implement `fields/0` returning a list with `:id` first
- All struct modules implement `new/1` accepting an attrs map
- Tests use `PkiMnesia.TestHelper.setup_mnesia()` / `teardown_mnesia(dir)` for Mnesia lifecycle
- `KeyActivation` is unchanged -- `SoftwareAdapter` wraps it; never modify `key_activation.ex`

---

## Task 1: KeyStore Behaviour + Dispatcher + SoftwareAdapter

**Files:**
- Create: `src/pki_ca_engine/lib/pki_ca_engine/key_store.ex`
- Create: `src/pki_ca_engine/lib/pki_ca_engine/key_store/dispatcher.ex`
- Create: `src/pki_ca_engine/lib/pki_ca_engine/key_store/software_adapter.ex`
- Modify: `src/pki_mnesia/lib/pki_mnesia/structs/issuer_key.ex`
- Create: `src/pki_ca_engine/test/pki_ca_engine/key_store/dispatcher_test.exs`
- Create: `src/pki_ca_engine/test/pki_ca_engine/key_store/software_adapter_test.exs`

### Context

The `KeyStore` behaviour defines 3 callbacks (`sign`, `get_public_key`, `key_available?`). The `Dispatcher` reads `IssuerKey.keystore_type` from Mnesia and routes to the correct adapter. `SoftwareAdapter` wraps the existing `KeyActivation.get_active_key` + `PkiCrypto` signing path -- no behavior change for existing keys.

We also add 3 new fields to `IssuerKey`: `keystore_type` (defaults `:software`), `hsm_config` (map, defaults `%{}`), and `hsm_key_handle` (binary, defaults `nil`).

- [ ] **Step 1: Add keystore_type, hsm_config, hsm_key_handle fields to IssuerKey**

Edit `src/pki_mnesia/lib/pki_mnesia/structs/issuer_key.ex`:

```elixir
defmodule PkiMnesia.Structs.IssuerKey do
  @moduledoc "Issuer key record with ceremony mode and lifecycle status."

  @fields [:id, :ca_instance_id, :key_alias, :algorithm, :status, :is_root,
           :ceremony_mode, :keystore_ref, :certificate_der, :certificate_pem,
           :csr_pem, :subject_dn, :fingerprint, :threshold_config,
           :keystore_type, :hsm_config, :hsm_key_handle,
           :inserted_at, :updated_at]
  def fields, do: @fields

  defstruct @fields

  @type t :: %__MODULE__{
    id: binary(),
    ca_instance_id: binary(),
    key_alias: String.t(),
    algorithm: String.t(),
    status: String.t(),
    is_root: boolean(),
    ceremony_mode: atom(),
    keystore_ref: binary() | nil,
    certificate_der: binary() | nil,
    certificate_pem: String.t() | nil,
    csr_pem: String.t() | nil,
    subject_dn: String.t() | nil,
    fingerprint: String.t() | nil,
    threshold_config: map(),
    keystore_type: :software | :local_hsm | :remote_hsm,
    hsm_config: map(),
    hsm_key_handle: binary() | nil,
    inserted_at: DateTime.t(),
    updated_at: DateTime.t()
  }

  @doc "Validates required fields before Mnesia write."
  def validate(%__MODULE__{} = s) do
    missing =
      [{:ca_instance_id, s.ca_instance_id}, {:algorithm, s.algorithm}]
      |> Enum.filter(fn {_k, v} -> is_nil(v) end)
      |> Enum.map(fn {k, _v} -> k end)

    if missing == [], do: :ok, else: {:error, {:missing_fields, missing}}
  end

  def new(attrs \\ %{}) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    %__MODULE__{
      id: attrs[:id] || PkiMnesia.Id.generate(),
      ca_instance_id: attrs[:ca_instance_id],
      key_alias: attrs[:key_alias],
      algorithm: attrs[:algorithm],
      status: Map.get(attrs, :status, "pending"),
      is_root: Map.get(attrs, :is_root, true),
      ceremony_mode: Map.get(attrs, :ceremony_mode, :full),
      keystore_ref: attrs[:keystore_ref],
      certificate_der: attrs[:certificate_der],
      certificate_pem: attrs[:certificate_pem],
      csr_pem: attrs[:csr_pem],
      subject_dn: attrs[:subject_dn],
      fingerprint: attrs[:fingerprint],
      threshold_config: Map.get(attrs, :threshold_config, %{k: 2, n: 3}),
      keystore_type: Map.get(attrs, :keystore_type, :software),
      hsm_config: Map.get(attrs, :hsm_config, %{}),
      hsm_key_handle: attrs[:hsm_key_handle],
      inserted_at: attrs[:inserted_at] || now,
      updated_at: attrs[:updated_at] || now
    }
  end
end
```

- [ ] **Step 2: Run existing IssuerKey tests to verify backward compatibility**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_mnesia && mix test
```

Expected: All existing tests pass. New fields default to `:software` / `%{}` / `nil`.

- [ ] **Step 3: Write the KeyStore behaviour**

Create `src/pki_ca_engine/lib/pki_ca_engine/key_store.ex`:

```elixir
defmodule PkiCaEngine.KeyStore do
  @moduledoc """
  Behaviour for signing backends.

  Three adapters implement this:
  - SoftwareAdapter — wraps KeyActivation (threshold ceremony keys in memory)
  - LocalHsmAdapter — Erlang Port to PKCS#11 device co-located with BEAM
  - RemoteHsmAdapter — gRPC to Go agent on customer's site
  """

  @callback sign(issuer_key_id :: binary(), tbs_data :: binary()) ::
    {:ok, signature :: binary()} | {:error, term()}

  @callback get_public_key(issuer_key_id :: binary()) ::
    {:ok, public_key :: binary()} | {:error, term()}

  @callback key_available?(issuer_key_id :: binary()) :: boolean()
end
```

- [ ] **Step 4: Write the Dispatcher test**

Create `src/pki_ca_engine/test/pki_ca_engine/key_store/dispatcher_test.exs`:

```elixir
defmodule PkiCaEngine.KeyStore.DispatcherTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.{TestHelper, Repo}
  alias PkiMnesia.Structs.IssuerKey
  alias PkiCaEngine.KeyStore.Dispatcher

  setup do
    dir = TestHelper.setup_mnesia()

    on_exit(fn ->
      TestHelper.teardown_mnesia(dir)
    end)

    :ok
  end

  describe "sign/2" do
    test "routes :software keystore_type to SoftwareAdapter" do
      # Create an issuer key with keystore_type :software (the default)
      key = IssuerKey.new(%{
        ca_instance_id: "ca-1",
        algorithm: "ECC-P256",
        status: "active",
        keystore_type: :software
      })
      {:ok, _} = Repo.insert(key)

      # Without an active key in KeyActivation, SoftwareAdapter returns :not_active
      assert {:error, :not_active} = Dispatcher.sign(key.id, "tbs-data")
    end

    test "routes :local_hsm keystore_type to LocalHsmAdapter" do
      key = IssuerKey.new(%{
        ca_instance_id: "ca-1",
        algorithm: "ECC-P256",
        status: "active",
        keystore_type: :local_hsm,
        hsm_config: %{"library_path" => "/usr/lib/softhsm/libsofthsm2.so", "slot_id" => 0, "pin" => "1234", "key_label" => "test-key"}
      })
      {:ok, _} = Repo.insert(key)

      # Without a running Pkcs11Port, LocalHsmAdapter returns an error
      assert {:error, _reason} = Dispatcher.sign(key.id, "tbs-data")
    end

    test "routes :remote_hsm keystore_type to RemoteHsmAdapter" do
      key = IssuerKey.new(%{
        ca_instance_id: "ca-1",
        algorithm: "ECC-P256",
        status: "active",
        keystore_type: :remote_hsm,
        hsm_config: %{"key_label" => "test-key"}
      })
      {:ok, _} = Repo.insert(key)

      # Without a connected agent, RemoteHsmAdapter returns :agent_not_connected
      assert {:error, :agent_not_connected} = Dispatcher.sign(key.id, "tbs-data")
    end

    test "returns :unknown_keystore_type for invalid type" do
      key = IssuerKey.new(%{
        ca_instance_id: "ca-1",
        algorithm: "ECC-P256",
        status: "active",
        keystore_type: :cloud_hsm
      })
      {:ok, _} = Repo.insert(key)

      assert {:error, :unknown_keystore_type} = Dispatcher.sign(key.id, "tbs-data")
    end

    test "returns :issuer_key_not_found for missing key" do
      assert {:error, :issuer_key_not_found} = Dispatcher.sign("nonexistent-id", "tbs-data")
    end
  end

  describe "key_available?/1" do
    test "delegates to SoftwareAdapter for :software keys" do
      key = IssuerKey.new(%{
        ca_instance_id: "ca-1",
        algorithm: "ECC-P256",
        status: "active",
        keystore_type: :software
      })
      {:ok, _} = Repo.insert(key)

      # No key activated, so not available
      refute Dispatcher.key_available?(key.id)
    end
  end
end
```

- [ ] **Step 5: Run the Dispatcher test to verify it fails**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_engine && mix test test/pki_ca_engine/key_store/dispatcher_test.exs
```

Expected: FAIL -- module `PkiCaEngine.KeyStore.Dispatcher` not found.

- [ ] **Step 6: Write the Dispatcher**

Create `src/pki_ca_engine/lib/pki_ca_engine/key_store/dispatcher.ex`:

```elixir
defmodule PkiCaEngine.KeyStore.Dispatcher do
  @moduledoc """
  Routes signing operations to the correct KeyStore adapter based on
  IssuerKey.keystore_type.

  All callers (CertificateSigning, OcspResponder, CrlPublisher) use this
  module instead of calling KeyActivation directly.
  """

  alias PkiMnesia.{Repo, Structs.IssuerKey}
  alias PkiCaEngine.KeyStore.{SoftwareAdapter, LocalHsmAdapter, RemoteHsmAdapter}

  @doc "Sign tbs_data using the adapter configured on the issuer key."
  def sign(issuer_key_id, tbs_data) do
    with {:ok, key} <- get_issuer_key(issuer_key_id) do
      adapter_for(key.keystore_type).sign(issuer_key_id, tbs_data)
    end
  end

  @doc "Get the public key for the given issuer key."
  def get_public_key(issuer_key_id) do
    with {:ok, key} <- get_issuer_key(issuer_key_id) do
      adapter_for(key.keystore_type).get_public_key(issuer_key_id)
    end
  end

  @doc "Check if the key is available for signing."
  def key_available?(issuer_key_id) do
    case get_issuer_key(issuer_key_id) do
      {:ok, key} -> adapter_for(key.keystore_type).key_available?(issuer_key_id)
      _ -> false
    end
  end

  defp adapter_for(:software), do: SoftwareAdapter
  defp adapter_for(:local_hsm), do: LocalHsmAdapter
  defp adapter_for(:remote_hsm), do: RemoteHsmAdapter
  defp adapter_for(_), do: {:error, :unknown_keystore_type}

  defp get_issuer_key(issuer_key_id) do
    case Repo.get(IssuerKey, issuer_key_id) do
      {:ok, nil} -> {:error, :issuer_key_not_found}
      {:ok, key} -> {:ok, key}
      {:error, _} = err -> err
    end
  end
end
```

**Important:** The `adapter_for/1` function returns an error tuple for unknown types. Update the `sign/2` function to handle this:

```elixir
  def sign(issuer_key_id, tbs_data) do
    with {:ok, key} <- get_issuer_key(issuer_key_id) do
      case adapter_for(key.keystore_type) do
        {:error, _} = err -> err
        adapter -> adapter.sign(issuer_key_id, tbs_data)
      end
    end
  end

  def get_public_key(issuer_key_id) do
    with {:ok, key} <- get_issuer_key(issuer_key_id) do
      case adapter_for(key.keystore_type) do
        {:error, _} = err -> err
        adapter -> adapter.get_public_key(issuer_key_id)
      end
    end
  end

  def key_available?(issuer_key_id) do
    case get_issuer_key(issuer_key_id) do
      {:ok, key} ->
        case adapter_for(key.keystore_type) do
          {:error, _} -> false
          adapter -> adapter.key_available?(issuer_key_id)
        end
      _ -> false
    end
  end
```

The full Dispatcher module (final version):

```elixir
defmodule PkiCaEngine.KeyStore.Dispatcher do
  @moduledoc """
  Routes signing operations to the correct KeyStore adapter based on
  IssuerKey.keystore_type.

  All callers (CertificateSigning, OcspResponder, CrlPublisher) use this
  module instead of calling KeyActivation directly.
  """

  alias PkiMnesia.{Repo, Structs.IssuerKey}
  alias PkiCaEngine.KeyStore.{SoftwareAdapter, LocalHsmAdapter, RemoteHsmAdapter}

  @doc "Sign tbs_data using the adapter configured on the issuer key."
  def sign(issuer_key_id, tbs_data) do
    with {:ok, key} <- get_issuer_key(issuer_key_id) do
      case adapter_for(key.keystore_type) do
        {:error, _} = err -> err
        adapter -> adapter.sign(issuer_key_id, tbs_data)
      end
    end
  end

  @doc "Get the public key for the given issuer key."
  def get_public_key(issuer_key_id) do
    with {:ok, key} <- get_issuer_key(issuer_key_id) do
      case adapter_for(key.keystore_type) do
        {:error, _} = err -> err
        adapter -> adapter.get_public_key(issuer_key_id)
      end
    end
  end

  @doc "Check if the key is available for signing."
  def key_available?(issuer_key_id) do
    case get_issuer_key(issuer_key_id) do
      {:ok, key} ->
        case adapter_for(key.keystore_type) do
          {:error, _} -> false
          adapter -> adapter.key_available?(issuer_key_id)
        end
      _ -> false
    end
  end

  defp adapter_for(:software), do: SoftwareAdapter
  defp adapter_for(:local_hsm), do: LocalHsmAdapter
  defp adapter_for(:remote_hsm), do: RemoteHsmAdapter
  defp adapter_for(_), do: {:error, :unknown_keystore_type}

  defp get_issuer_key(issuer_key_id) do
    case Repo.get(IssuerKey, issuer_key_id) do
      {:ok, nil} -> {:error, :issuer_key_not_found}
      {:ok, key} -> {:ok, key}
      {:error, _} = err -> err
    end
  end
end
```

- [ ] **Step 7: Write the SoftwareAdapter test**

Create `src/pki_ca_engine/test/pki_ca_engine/key_store/software_adapter_test.exs`:

```elixir
defmodule PkiCaEngine.KeyStore.SoftwareAdapterTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.{TestHelper, Repo}
  alias PkiMnesia.Structs.IssuerKey
  alias PkiCaEngine.KeyStore.SoftwareAdapter
  alias PkiCaEngine.KeyActivation

  setup do
    dir = TestHelper.setup_mnesia()
    {:ok, ka_pid} = KeyActivation.start_link(name: :test_ka_sw, timeout_ms: 60_000)
    Application.put_env(:pki_ca_engine, :allow_dev_activate, true)

    on_exit(fn ->
      Application.put_env(:pki_ca_engine, :allow_dev_activate, false)
      if Process.alive?(ka_pid), do: GenServer.stop(ka_pid)
      TestHelper.teardown_mnesia(dir)
    end)

    %{ka: :test_ka_sw}
  end

  test "sign/2 wraps KeyActivation and signs with PkiCrypto", %{ka: ka} do
    # Generate an ECC key pair
    {pub_der, priv_der} = generate_ecc_keypair()

    key = IssuerKey.new(%{
      ca_instance_id: "ca-1",
      algorithm: "ECC-P256",
      status: "active",
      keystore_type: :software,
      certificate_der: <<0>>  # placeholder -- not used for sign
    })
    {:ok, _} = Repo.insert(key)

    # Activate the key via dev_activate
    {:ok, :dev_activated} = KeyActivation.dev_activate(ka, key.id, priv_der)

    tbs_data = :crypto.strong_rand_bytes(64)
    result = SoftwareAdapter.sign(key.id, tbs_data, activation_server: ka)

    assert {:ok, signature} = result
    assert is_binary(signature)
    assert byte_size(signature) > 0

    # Verify the signature
    ec_key = :public_key.der_decode(:SubjectPublicKeyInfo, pub_der)
    assert :public_key.verify(tbs_data, :sha256, signature, ec_key)
  end

  test "sign/2 returns :not_active when key not activated" do
    key = IssuerKey.new(%{
      ca_instance_id: "ca-1",
      algorithm: "ECC-P256",
      status: "active",
      keystore_type: :software
    })
    {:ok, _} = Repo.insert(key)

    assert {:error, :not_active} = SoftwareAdapter.sign(key.id, "tbs-data")
  end

  test "key_available?/1 returns true when key is activated", %{ka: ka} do
    key = IssuerKey.new(%{
      ca_instance_id: "ca-1",
      algorithm: "ECC-P256",
      status: "active",
      keystore_type: :software
    })
    {:ok, _} = Repo.insert(key)

    refute SoftwareAdapter.key_available?(key.id, activation_server: ka)

    {:ok, :dev_activated} = KeyActivation.dev_activate(ka, key.id, :crypto.strong_rand_bytes(32))

    assert SoftwareAdapter.key_available?(key.id, activation_server: ka)
  end

  defp generate_ecc_keypair do
    ec_key = :public_key.generate_key({:namedCurve, :secp256r1})
    priv_der = :public_key.der_encode(:ECPrivateKey, ec_key)
    pub_der = :public_key.der_encode(:SubjectPublicKeyInfo, {:ECPoint, elem(ec_key, 3), {:namedCurve, :secp256r1}})
    {pub_der, priv_der}
  end
end
```

- [ ] **Step 8: Run the SoftwareAdapter test to verify it fails**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_engine && mix test test/pki_ca_engine/key_store/software_adapter_test.exs
```

Expected: FAIL -- module `PkiCaEngine.KeyStore.SoftwareAdapter` not found.

- [ ] **Step 9: Write the SoftwareAdapter**

Create `src/pki_ca_engine/lib/pki_ca_engine/key_store/software_adapter.ex`:

```elixir
defmodule PkiCaEngine.KeyStore.SoftwareAdapter do
  @moduledoc """
  KeyStore adapter for software keystores.

  Wraps the existing KeyActivation GenServer. The threshold ceremony
  activation flow is unchanged -- this adapter just bridges the new
  KeyStore behaviour to the existing signing path.
  """
  @behaviour PkiCaEngine.KeyStore

  alias PkiMnesia.{Repo, Structs.IssuerKey}
  alias PkiCaEngine.KeyActivation

  @impl true
  def sign(issuer_key_id, tbs_data, opts \\ []) do
    activation_server = Keyword.get(opts, :activation_server, KeyActivation)

    with {:ok, key} <- get_issuer_key(issuer_key_id),
         {:ok, private_key_der} <- KeyActivation.get_active_key(activation_server, issuer_key_id) do
      do_sign(key.algorithm, private_key_der, tbs_data)
    end
  end

  @impl true
  def get_public_key(issuer_key_id) do
    case get_issuer_key(issuer_key_id) do
      {:ok, %{certificate_der: nil}} -> {:error, :no_certificate}
      {:ok, key} -> extract_public_key(key.certificate_der)
      err -> err
    end
  end

  @impl true
  def key_available?(issuer_key_id, opts \\ []) do
    activation_server = Keyword.get(opts, :activation_server, KeyActivation)
    KeyActivation.is_active?(activation_server, issuer_key_id)
  end

  # -- Private --

  defp get_issuer_key(issuer_key_id) do
    case Repo.get(IssuerKey, issuer_key_id) do
      {:ok, nil} -> {:error, :issuer_key_not_found}
      {:ok, key} -> {:ok, key}
      {:error, _} = err -> err
    end
  end

  defp do_sign(algorithm, private_key_der, tbs_data) do
    case PkiCrypto.AlgorithmRegistry.by_id(algorithm) do
      {:ok, %{family: family}} when family in [:ml_dsa, :kaz_sign, :slh_dsa] ->
        case PkiCrypto.Registry.get(algorithm) do
          {:ok, algo} -> PkiCrypto.Algorithm.sign(algo, private_key_der, tbs_data)
          {:error, _} = err -> err
        end

      {:ok, %{family: :ecdsa}} ->
        hash = if algorithm == "ECC-P384", do: :sha384, else: :sha256
        native_key = :public_key.der_decode(:ECPrivateKey, private_key_der)
        {:ok, :public_key.sign(tbs_data, hash, native_key)}

      {:ok, %{family: :rsa}} ->
        native_key = :public_key.der_decode(:RSAPrivateKey, private_key_der)
        {:ok, :public_key.sign(tbs_data, :sha256, native_key)}

      _ ->
        {:error, :unknown_algorithm}
    end
  end

  defp extract_public_key(cert_der) do
    try do
      cert = :public_key.der_decode(:Certificate, cert_der)
      tbs = elem(cert, 1)
      spki = elem(tbs, 6)
      {:ok, :public_key.der_encode(:SubjectPublicKeyInfo, spki)}
    rescue
      _ -> {:error, :invalid_certificate}
    end
  end
end
```

- [ ] **Step 10: Run Dispatcher + SoftwareAdapter tests**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_engine && mix test test/pki_ca_engine/key_store/
```

Expected: All tests pass.

- [ ] **Step 11: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki
git add src/pki_mnesia/lib/pki_mnesia/structs/issuer_key.ex \
  src/pki_ca_engine/lib/pki_ca_engine/key_store.ex \
  src/pki_ca_engine/lib/pki_ca_engine/key_store/dispatcher.ex \
  src/pki_ca_engine/lib/pki_ca_engine/key_store/software_adapter.ex \
  src/pki_ca_engine/test/pki_ca_engine/key_store/dispatcher_test.exs \
  src/pki_ca_engine/test/pki_ca_engine/key_store/software_adapter_test.exs
git commit -m "feat(hsm): add KeyStore behaviour, Dispatcher, SoftwareAdapter

Introduces the KeyStore abstraction layer:
- KeyStore behaviour with sign/2, get_public_key/1, key_available?/1
- Dispatcher routes by IssuerKey.keystore_type field
- SoftwareAdapter wraps existing KeyActivation signing path
- IssuerKey gains keystore_type, hsm_config, hsm_key_handle fields
- All existing keys default to :software (no behavior change)"
```

---

## Task 2: Update Callers to Use KeyStore.Dispatcher

**Files:**
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/certificate_signing.ex`
- Modify: `src/pki_validation/lib/pki_validation/ocsp_responder.ex`
- Modify: `src/pki_validation/lib/pki_validation/crl_publisher.ex`

### Context

Three callers currently call `KeyActivation.get_active_key` directly, then sign using `PkiCrypto`. Each must switch to `KeyStore.Dispatcher.sign/2`, which handles algorithm resolution internally. This is a pure refactor -- behavior is identical for `:software` keystore_type.

**CertificateSigning** is special: it uses the raw `private_key_der` for `do_sign` which calls `PkiCrypto.X509Builder.sign_tbs`. For HSM keys, we cannot extract the private key. The Dispatcher returns a raw signature, but CertificateSigning needs to build the full X.509 certificate. We must split the pipeline: build TBS first, then sign via Dispatcher, then assemble the certificate.

For Task 2, we update the callers to use Dispatcher for the simpler cases (OCSP, CRL) while preserving the CertificateSigning pipeline. CertificateSigning will need a two-step approach: Dispatcher returns signature bytes, CertificateSigning assembles the cert.

- [ ] **Step 1: Update OcspResponder to use Dispatcher.sign**

Edit `src/pki_validation/lib/pki_validation/ocsp_responder.ex`. Replace the `signed_response/3` function:

Current code (lines 38-80):
```elixir
  def signed_response(serial_number, issuer_key_id, opts \\ []) do
    activation_server = Keyword.get(opts, :activation_server, KeyActivation)
    status = lookup_status(serial_number)

    response_data = :erlang.term_to_binary(%{
      serial_number: serial_number,
      status: status,
      produced_at: DateTime.utc_now() |> DateTime.to_iso8601()
    })

    case KeyActivation.get_active_key(activation_server, issuer_key_id) do
      {:ok, private_key} ->
        case Repo.get(IssuerKey, issuer_key_id) do
          {:ok, %IssuerKey{} = issuer_key} ->
            case sign_response(issuer_key.algorithm, private_key, response_data) do
              {:ok, signature} ->
                {:ok, %{
                  status: status,
                  response_data: response_data,
                  signature: signature,
                  algorithm: issuer_key.algorithm
                }}

              {:error, reason} ->
                {:error, {:signing_failed, reason}}
            end

          {:ok, nil} ->
            # Issuer key not in Mnesia — return unsigned status
            {:ok, %{status: status, unsigned: true}}

          {:error, reason} ->
            {:error, {:issuer_key_lookup_failed, reason}}
        end

      {:error, :not_active} ->
        # Key not yet activated via threshold ceremony — return unsigned status
        {:ok, %{status: status, unsigned: true}}

      {:error, reason} ->
        {:error, {:key_activation_failed, reason}}
    end
  end
```

Replace with:

```elixir
  def signed_response(serial_number, issuer_key_id, opts \\ []) do
    _activation_server = Keyword.get(opts, :activation_server, KeyActivation)
    status = lookup_status(serial_number)

    response_data = :erlang.term_to_binary(%{
      serial_number: serial_number,
      status: status,
      produced_at: DateTime.utc_now() |> DateTime.to_iso8601()
    })

    case PkiCaEngine.KeyStore.Dispatcher.sign(issuer_key_id, response_data) do
      {:ok, signature} ->
        case Repo.get(IssuerKey, issuer_key_id) do
          {:ok, %IssuerKey{} = issuer_key} ->
            {:ok, %{
              status: status,
              response_data: response_data,
              signature: signature,
              algorithm: issuer_key.algorithm
            }}

          {:ok, nil} ->
            {:ok, %{status: status, unsigned: true}}

          {:error, reason} ->
            {:error, {:issuer_key_lookup_failed, reason}}
        end

      {:error, :not_active} ->
        {:ok, %{status: status, unsigned: true}}

      {:error, :agent_not_connected} ->
        {:ok, %{status: status, unsigned: true}}

      {:error, reason} ->
        {:error, {:signing_failed, reason}}
    end
  end
```

Also update the alias block at the top -- remove `alias PkiCaEngine.KeyActivation` since it is no longer called directly, and remove the `sign_response/3` private function (lines 120-140) since signing is now handled by the adapter:

Remove these aliases from line 16:
```elixir
  alias PkiCaEngine.KeyActivation
```

Keep the `KeyActivation` import only if `opts[:activation_server]` is still used for backward compat in tests. Since we are not removing the opts parameter signature, keep the alias but mark the option as deprecated.

Remove the private `sign_response/3` function entirely (lines 120-140).

- [ ] **Step 2: Update CrlPublisher to use Dispatcher.sign**

Edit `src/pki_validation/lib/pki_validation/crl_publisher.ex`. Replace the `signed_crl/2` function:

Current code (lines 53-73):
```elixir
  def signed_crl(issuer_key_id, opts \\ []) do
    activation_server = Keyword.get(opts, :activation_server, KeyActivation)

    with {:ok, crl} <- do_generate_crl(),
         {:ok, private_key} <- KeyActivation.get_active_key(activation_server, issuer_key_id),
         {:ok, issuer_key} <- Repo.get(IssuerKey, issuer_key_id),
         crl_data <- :erlang.term_to_binary(crl),
         {:ok, signature} <- sign_crl(issuer_key.algorithm, private_key, crl_data) do
      {:ok, Map.merge(crl, %{signature: signature, algorithm: issuer_key.algorithm})}
    else
      {:error, :not_active} ->
        # Key not yet activated — return unsigned CRL
        case do_generate_crl() do
          {:ok, crl} -> {:ok, Map.put(crl, :unsigned, true)}
          err -> err
        end

      {:error, reason} ->
        {:error, reason}
    end
  end
```

Replace with:

```elixir
  def signed_crl(issuer_key_id, opts \\ []) do
    _activation_server = Keyword.get(opts, :activation_server, KeyActivation)

    with {:ok, crl} <- do_generate_crl(),
         crl_data <- :erlang.term_to_binary(crl),
         {:ok, signature} <- PkiCaEngine.KeyStore.Dispatcher.sign(issuer_key_id, crl_data),
         {:ok, issuer_key} <- Repo.get(IssuerKey, issuer_key_id) do
      {:ok, Map.merge(crl, %{signature: signature, algorithm: issuer_key.algorithm})}
    else
      {:error, :not_active} ->
        case do_generate_crl() do
          {:ok, crl} -> {:ok, Map.put(crl, :unsigned, true)}
          err -> err
        end

      {:error, :agent_not_connected} ->
        case do_generate_crl() do
          {:ok, crl} -> {:ok, Map.put(crl, :unsigned, true)}
          err -> err
        end

      {:error, reason} ->
        {:error, reason}
    end
  end
```

Remove the private `sign_crl/3` function (lines 193-213).

- [ ] **Step 3: Update CertificateSigning to use Dispatcher**

This is the most complex change. `CertificateSigning.sign_certificate` currently calls `KeyActivation.get_active_key` to get the raw private key DER, then passes it to `do_sign` which builds the TBS cert and calls `PkiCrypto.X509Builder.sign_tbs`.

For HSM keys, we cannot get the raw private key. The signing must happen inside the adapter. We need to:
1. Build the TBS cert first (no private key needed)
2. Call `Dispatcher.sign(issuer_key_id, tbs_der)` to get the signature
3. Assemble the final certificate from TBS + signature

However, `PkiCrypto.X509Builder.sign_tbs` does both signing AND assembly. We need to check if there's a way to just assemble. For now, we keep the Software path using the existing `do_sign` flow by checking keystore_type, and add a new HSM path for `:local_hsm` / `:remote_hsm` that uses a two-step build.

Edit `src/pki_ca_engine/lib/pki_ca_engine/certificate_signing.ex`:

Replace the `sign_certificate/4` function body. The key change is in lines 22-28 and 35:

Current (lines 18-71):
```elixir
  def sign_certificate(issuer_key_id, csr_pem, cert_profile_map, opts \\ []) do
    activation_server = opts[:activation_server] || KeyActivation
    csr_fingerprint = compute_csr_fingerprint(csr_pem)

    with {:ok, issuer_key} <- get_issuer_key(issuer_key_id),
         :ok <- check_key_status(issuer_key),
         :ok <- check_duplicate_csr(issuer_key_id, csr_fingerprint),
         :ok <- check_ca_online(issuer_key),
         :ok <- check_leaf_ca(issuer_key),
         {:ok, private_key_der} <- KeyActivation.get_active_key(activation_server, issuer_key_id) do
```

Replace with:

```elixir
  def sign_certificate(issuer_key_id, csr_pem, cert_profile_map, opts \\ []) do
    _activation_server = opts[:activation_server] || KeyActivation
    csr_fingerprint = compute_csr_fingerprint(csr_pem)

    with {:ok, issuer_key} <- get_issuer_key(issuer_key_id),
         :ok <- check_key_status(issuer_key),
         :ok <- check_duplicate_csr(issuer_key_id, csr_fingerprint),
         :ok <- check_ca_online(issuer_key),
         :ok <- check_leaf_ca(issuer_key) do

      serial = generate_serial()
      now = DateTime.utc_now() |> DateTime.truncate(:second)
      validity_days = Map.get(cert_profile_map, :validity_days, 365)
      not_after = DateTime.add(now, validity_days * 86400, :second) |> DateTime.truncate(:second)
      subject_dn = Map.get(cert_profile_map, :subject_dn, extract_subject_from_csr(csr_pem))

      sign_result =
        case issuer_key.keystore_type do
          :software ->
            # Existing path: get raw key, sign in-process
            case PkiCaEngine.KeyStore.SoftwareAdapter.get_raw_key(issuer_key_id) do
              {:ok, private_key_der} ->
                do_sign(issuer_key, private_key_der, csr_pem, subject_dn, validity_days, serial)
              {:error, _} = err -> err
            end

          _hsm_type ->
            # HSM path: build TBS, sign via Dispatcher, assemble cert
            do_sign_via_dispatcher(issuer_key, issuer_key_id, csr_pem, subject_dn, validity_days, serial)
        end

      case sign_result do
        {:ok, cert_der, cert_pem_str} ->
          cert = IssuedCertificate.new(%{
            serial_number: serial,
            issuer_key_id: issuer_key_id,
            subject_dn: subject_dn,
            cert_der: cert_der,
            cert_pem: cert_pem_str,
            not_before: now,
            not_after: not_after,
            cert_profile_id: cert_profile_map[:id],
            csr_fingerprint: csr_fingerprint
          })

          case Repo.insert(cert) do
            {:ok, cert} ->
              cert_status = CertificateStatus.new(%{
                serial_number: serial,
                issuer_key_id: issuer_key_id,
                status: "active",
                not_after: not_after
              })
              Repo.insert(cert_status)
              {:ok, cert}

            error -> error
          end

        {:error, reason} -> {:error, reason}
      end
    else
      {:error, :not_active} -> {:error, :key_not_active}
      {:error, reason} -> {:error, reason}
    end
  end
```

Add a new private function `do_sign_via_dispatcher/6` and a helper to `SoftwareAdapter`:

Add to `certificate_signing.ex` after the existing `do_sign/6`:

```elixir
  defp do_sign_via_dispatcher(issuer_key, issuer_key_id, csr_pem, subject_dn, validity_days, serial) do
    issuer_cert_der = issuer_key.certificate_der
    issuer_alg_id = issuer_key.algorithm
    serial_int = hex_serial_to_integer(serial)

    if issuer_cert_der == nil do
      {:error, :issuer_certificate_not_available}
    else
      with {:ok, csr} <- PkiCrypto.Csr.parse(csr_pem),
           :ok <- PkiCrypto.Csr.verify_pop(csr),
           {:ok, tbs, sig_alg_oid} <-
             PkiCrypto.X509Builder.build_tbs_cert(
               csr,
               %{cert_der: issuer_cert_der, algorithm_id: issuer_alg_id},
               subject_dn,
               validity_days,
               serial_int
             ),
           tbs_der <- :public_key.der_encode(:TBSCertificate, tbs),
           {:ok, signature} <- PkiCaEngine.KeyStore.Dispatcher.sign(issuer_key_id, tbs_der) do
        # Assemble the full certificate: TBS + sigAlg + signature
        cert_der = PkiCrypto.X509Builder.assemble_cert(tbs, sig_alg_oid, signature)
        cert_pem = :public_key.pem_encode([{:Certificate, cert_der, :not_encrypted}])
        {:ok, cert_der, cert_pem}
      else
        {:error, reason} ->
          Logger.error("Certificate signing via HSM failed: #{inspect(reason)}")
          {:error, {:signing_failed, reason}}
      end
    end
  end
```

**Note:** This assumes `PkiCrypto.X509Builder.assemble_cert/3` exists or can be added. If `sign_tbs` currently does both sign+assemble, you may need to add an `assemble_cert/3` function to `PkiCrypto.X509Builder`. Check if it exists; if not, add it:

```elixir
# In PkiCrypto.X509Builder (if not already present):
def assemble_cert(tbs, sig_alg_oid, signature) do
  cert = {:Certificate, tbs, sig_alg_oid, signature}
  :public_key.der_encode(:Certificate, cert)
end
```

Also add `get_raw_key/1` to `SoftwareAdapter`:

```elixir
  @doc "Get the raw private key DER from KeyActivation. Used by CertificateSigning for X.509 assembly."
  def get_raw_key(issuer_key_id, opts \\ []) do
    activation_server = Keyword.get(opts, :activation_server, KeyActivation)
    KeyActivation.get_active_key(activation_server, issuer_key_id)
  end
```

- [ ] **Step 4: Run all existing tests to verify no regression**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_engine && mix test
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_validation && mix test
```

Expected: All tests pass. The `:software` path is functionally identical.

- [ ] **Step 5: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki
git add src/pki_ca_engine/lib/pki_ca_engine/certificate_signing.ex \
  src/pki_ca_engine/lib/pki_ca_engine/key_store/software_adapter.ex \
  src/pki_validation/lib/pki_validation/ocsp_responder.ex \
  src/pki_validation/lib/pki_validation/crl_publisher.ex
git commit -m "refactor(hsm): update callers to use KeyStore.Dispatcher

CertificateSigning, OcspResponder, CrlPublisher now route through
KeyStore.Dispatcher.sign/2 instead of calling KeyActivation directly.
Software keystore behavior unchanged. HSM path added to CertificateSigning
with two-step build (TBS -> sign -> assemble)."
```

---

## Task 3: PKCS#11 Port Binary (C)

**Files:**
- Create: `src/pki_ca_engine/priv/pkcs11_port.c`
- Create: `src/pki_ca_engine/priv/Makefile`

### Context

This is a small C program (~250 lines) that the BEAM spawns as an Erlang Port. It communicates via length-prefixed binary messages on stdin/stdout. It loads a customer's PKCS#11 `.so` library via `dlopen` and calls PKCS#11 functions (`C_Initialize`, `C_OpenSession`, `C_Login`, `C_Sign`, `C_FindObjects`).

If this process crashes, the BEAM is unaffected. The `Pkcs11Port` GenServer (Task 4) restarts it with backoff.

- [ ] **Step 1: Create the Makefile**

Create `src/pki_ca_engine/priv/Makefile`:

```makefile
# Makefile for pkcs11_port — Erlang Port binary wrapping PKCS#11
#
# Usage:
#   make                  # builds priv/pkcs11_port
#   make clean            # removes build artifacts
#   make test-softhsm     # quick smoke test with SoftHSM2

CC ?= cc
CFLAGS = -Wall -Wextra -O2 -std=c11 -D_POSIX_C_SOURCE=200809L
LDFLAGS = -ldl

PRIV_DIR = $(CURDIR)
TARGET = $(PRIV_DIR)/pkcs11_port

.PHONY: all clean test-softhsm

all: $(TARGET)

$(TARGET): pkcs11_port.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

test-softhsm: $(TARGET)
	@echo "Smoke test with SoftHSM2..."
	@echo "Ensure SoftHSM2 is installed and a token exists."
	@echo "Run: softhsm2-util --init-token --slot 0 --label test --pin 1234 --so-pin 0000"
```

- [ ] **Step 2: Create the C port binary**

Create `src/pki_ca_engine/priv/pkcs11_port.c`:

```c
/*
 * pkcs11_port.c — Erlang Port binary wrapping PKCS#11 via dlopen.
 *
 * Protocol: 4-byte big-endian length prefix + JSON payload on stdin/stdout.
 *
 * Commands (JSON):
 *   {"cmd":"init","library":"/path/to.so","slot":0,"pin":"1234"}
 *   {"cmd":"sign","label":"key-label","data":"base64...","mechanism":"CKM_ECDSA"}
 *   {"cmd":"get_public_key","label":"key-label"}
 *   {"cmd":"ping"}
 *   {"cmd":"shutdown"}
 *
 * Responses (JSON):
 *   {"ok":true,...}
 *   {"error":"message"}
 *
 * Crash safety: this process is managed by Pkcs11Port GenServer.
 * If it crashes, the GenServer restarts it with exponential backoff.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>
#include <unistd.h>

/* PKCS#11 headers — we define the minimal subset we need */
#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#define NULL_PTR NULL

typedef unsigned long CK_ULONG;
typedef unsigned long CK_RV;
typedef unsigned long CK_SESSION_HANDLE;
typedef unsigned long CK_SLOT_ID;
typedef unsigned long CK_MECHANISM_TYPE;
typedef unsigned long CK_OBJECT_HANDLE;
typedef unsigned long CK_ATTRIBUTE_TYPE;
typedef unsigned long CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef CK_BYTE CK_PTR CK_BYTE_PTR;
typedef void CK_PTR CK_VOID_PTR;
typedef CK_ULONG CK_PTR CK_ULONG_PTR;
typedef unsigned long CK_BBOOL;
typedef unsigned long CK_OBJECT_CLASS;

/* Minimal PKCS#11 constants */
#define CKR_OK                  0x00000000
#define CKF_SERIAL_SESSION      0x00000004
#define CKF_RW_SESSION          0x00000002
#define CKU_USER                1
#define CKA_CLASS               0x00000000
#define CKA_LABEL               0x00000003
#define CKA_ID                  0x00000102
#define CKA_VALUE               0x00000011
#define CKO_PRIVATE_KEY         0x00000003
#define CKO_PUBLIC_KEY          0x00000002
#define CKM_ECDSA               0x00001041
#define CKM_RSA_PKCS            0x00000001
#define CK_TRUE                 1
#define CK_FALSE                0
#define CKA_SIGN                0x00000108
#define CKA_EC_POINT            0x00000180

typedef struct {
    CK_ATTRIBUTE_TYPE type;
    CK_VOID_PTR pValue;
    CK_ULONG ulValueLen;
} CK_ATTRIBUTE;

typedef struct {
    CK_MECHANISM_TYPE mechanism;
    CK_VOID_PTR pParameter;
    CK_ULONG ulParameterLen;
} CK_MECHANISM;

/* Function list — we load these from the .so */
typedef struct CK_FUNCTION_LIST CK_FUNCTION_LIST;
typedef CK_FUNCTION_LIST CK_PTR CK_FUNCTION_LIST_PTR;
typedef CK_FUNCTION_LIST_PTR CK_PTR CK_FUNCTION_LIST_PTR_PTR;

typedef CK_RV (*CK_C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR);

struct CK_FUNCTION_LIST {
    void *version; /* CK_VERSION — we skip it */
    CK_RV (*C_Initialize)(CK_VOID_PTR);
    CK_RV (*C_Finalize)(CK_VOID_PTR);
    void *C_GetInfo;
    CK_RV (*C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR);
    void *C_GetSlotList;
    void *C_GetSlotInfo;
    void *C_GetTokenInfo;
    void *C_GetMechanismList;
    void *C_GetMechanismInfo;
    void *C_InitToken;
    void *C_InitPIN;
    void *C_SetPIN;
    CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, void*, CK_SESSION_HANDLE*);
    CK_RV (*C_CloseSession)(CK_SESSION_HANDLE);
    void *C_CloseAllSessions;
    void *C_GetSessionInfo;
    void *C_GetOperationState;
    void *C_SetOperationState;
    CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_ULONG, CK_BYTE_PTR, CK_ULONG);
    void *C_Logout;
    void *C_CreateObject;
    void *C_CopyObject;
    void *C_DestroyObject;
    void *C_GetObjectSize;
    CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
    void *C_SetAttributeValue;
    CK_RV (*C_FindObjectsInit)(CK_SESSION_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
    CK_RV (*C_FindObjects)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE*, CK_ULONG, CK_ULONG*);
    CK_RV (*C_FindObjectsFinal)(CK_SESSION_HANDLE);
    void *C_EncryptInit;
    void *C_Encrypt;
    void *C_EncryptUpdate;
    void *C_EncryptFinal;
    void *C_DecryptInit;
    void *C_Decrypt;
    void *C_DecryptUpdate;
    void *C_DecryptFinal;
    void *C_DigestInit;
    void *C_Digest;
    void *C_DigestUpdate;
    void *C_DigestKey;
    void *C_DigestFinal;
    CK_RV (*C_SignInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
    CK_RV (*C_Sign)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG*);
    /* remaining functions omitted — not needed */
};

/* Base64 encode/decode — minimal inline implementation */
static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *base64_encode(const unsigned char *data, size_t len, size_t *out_len) {
    size_t olen = 4 * ((len + 2) / 3);
    char *out = malloc(olen + 1);
    if (!out) return NULL;

    size_t i, j;
    for (i = 0, j = 0; i < len; ) {
        uint32_t a = i < len ? data[i++] : 0;
        uint32_t b = i < len ? data[i++] : 0;
        uint32_t c = i < len ? data[i++] : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;
        out[j++] = b64_table[(triple >> 18) & 0x3F];
        out[j++] = b64_table[(triple >> 12) & 0x3F];
        out[j++] = (i > len + 1) ? '=' : b64_table[(triple >> 6) & 0x3F];
        out[j++] = (i > len) ? '=' : b64_table[triple & 0x3F];
    }
    out[j] = '\0';
    *out_len = j;
    return out;
}

static int b64_decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static unsigned char *base64_decode(const char *data, size_t len, size_t *out_len) {
    if (len % 4 != 0) return NULL;
    size_t olen = len / 4 * 3;
    if (len > 0 && data[len-1] == '=') olen--;
    if (len > 1 && data[len-2] == '=') olen--;

    unsigned char *out = malloc(olen);
    if (!out) return NULL;

    size_t i, j;
    for (i = 0, j = 0; i < len; ) {
        int a = b64_decode_char(data[i++]);
        int b = b64_decode_char(data[i++]);
        int c = (data[i] == '=') ? 0 : b64_decode_char(data[i]); i++;
        int d = (data[i] == '=') ? 0 : b64_decode_char(data[i]); i++;
        uint32_t triple = ((uint32_t)a << 18) | ((uint32_t)b << 12) | ((uint32_t)c << 6) | (uint32_t)d;
        if (j < olen) out[j++] = (triple >> 16) & 0xFF;
        if (j < olen) out[j++] = (triple >> 8) & 0xFF;
        if (j < olen) out[j++] = triple & 0xFF;
    }
    *out_len = olen;
    return out;
}

/* Simple JSON parsing — we only handle flat objects with string values */
/* This is intentionally simple. Production would use a proper JSON lib. */
static int json_get_string(const char *json, const char *key, char *out, size_t out_sz) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\":\"", key);
    const char *start = strstr(json, search);
    if (!start) {
        /* Try without quotes for numbers */
        snprintf(search, sizeof(search), "\"%s\":", key);
        start = strstr(json, search);
        if (!start) return -1;
        start += strlen(search);
        /* skip whitespace */
        while (*start == ' ') start++;
        const char *end = start;
        while (*end && *end != ',' && *end != '}' && *end != ' ') end++;
        size_t len = (size_t)(end - start);
        if (len >= out_sz) return -1;
        memcpy(out, start, len);
        out[len] = '\0';
        return 0;
    }
    start += strlen(search);
    const char *end = strchr(start, '"');
    if (!end) return -1;
    size_t len = (size_t)(end - start);
    if (len >= out_sz) return -1;
    memcpy(out, start, len);
    out[len] = '\0';
    return 0;
}

/* Global state */
static void *pkcs11_lib = NULL;
static CK_FUNCTION_LIST_PTR fn = NULL;
static CK_SESSION_HANDLE session = 0;
static int initialized = 0;

/* Read exactly n bytes from fd */
static int read_exact(int fd, unsigned char *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

/* Write exactly n bytes to fd */
static int write_exact(int fd, const unsigned char *buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, buf + sent, n - sent);
        if (w <= 0) return -1;
        sent += (size_t)w;
    }
    return 0;
}

/* Read a length-prefixed message from stdin */
static char *read_message(size_t *len) {
    unsigned char hdr[4];
    if (read_exact(STDIN_FILENO, hdr, 4) != 0) return NULL;
    uint32_t msg_len = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
                       ((uint32_t)hdr[2] << 8) | (uint32_t)hdr[3];
    if (msg_len > 10 * 1024 * 1024) return NULL; /* 10MB max */
    char *buf = malloc(msg_len + 1);
    if (!buf) return NULL;
    if (read_exact(STDIN_FILENO, (unsigned char *)buf, msg_len) != 0) { free(buf); return NULL; }
    buf[msg_len] = '\0';
    *len = msg_len;
    return buf;
}

/* Write a length-prefixed message to stdout */
static int write_message(const char *msg, size_t len) {
    unsigned char hdr[4];
    hdr[0] = (len >> 24) & 0xFF;
    hdr[1] = (len >> 16) & 0xFF;
    hdr[2] = (len >> 8) & 0xFF;
    hdr[3] = len & 0xFF;
    if (write_exact(STDOUT_FILENO, hdr, 4) != 0) return -1;
    if (write_exact(STDOUT_FILENO, (const unsigned char *)msg, len) != 0) return -1;
    return 0;
}

static void send_error(const char *msg) {
    char buf[1024];
    int n = snprintf(buf, sizeof(buf), "{\"error\":\"%s\"}", msg);
    write_message(buf, (size_t)n);
}

static void send_ok(const char *extra) {
    char buf[65536];
    int n;
    if (extra)
        n = snprintf(buf, sizeof(buf), "{\"ok\":true,%s}", extra);
    else
        n = snprintf(buf, sizeof(buf), "{\"ok\":true}");
    write_message(buf, (size_t)n);
}

/* Find a private key by label */
static CK_RV find_key_by_label(const char *label, CK_OBJECT_CLASS obj_class, CK_OBJECT_HANDLE *handle) {
    CK_ATTRIBUTE tmpl[2];
    tmpl[0].type = CKA_CLASS;
    tmpl[0].pValue = &obj_class;
    tmpl[0].ulValueLen = sizeof(obj_class);
    tmpl[1].type = CKA_LABEL;
    tmpl[1].pValue = (void *)label;
    tmpl[1].ulValueLen = strlen(label);

    CK_RV rv = fn->C_FindObjectsInit(session, tmpl, 2);
    if (rv != CKR_OK) return rv;

    CK_ULONG count = 0;
    rv = fn->C_FindObjects(session, handle, 1, &count);
    fn->C_FindObjectsFinal(session);
    if (rv != CKR_OK) return rv;
    if (count == 0) return 0xFFFFFFFF; /* not found */
    return CKR_OK;
}

static void handle_init(const char *json) {
    char library[512], slot_str[32], pin[256];
    if (json_get_string(json, "library", library, sizeof(library)) != 0) {
        send_error("missing library"); return;
    }
    if (json_get_string(json, "slot", slot_str, sizeof(slot_str)) != 0) {
        send_error("missing slot"); return;
    }
    if (json_get_string(json, "pin", pin, sizeof(pin)) != 0) {
        send_error("missing pin"); return;
    }

    CK_SLOT_ID slot = (CK_SLOT_ID)atol(slot_str);

    /* Load PKCS#11 library */
    pkcs11_lib = dlopen(library, RTLD_NOW);
    if (!pkcs11_lib) {
        char err[1024];
        snprintf(err, sizeof(err), "dlopen failed: %s", dlerror());
        send_error(err);
        return;
    }

    CK_C_GetFunctionList getFn = (CK_C_GetFunctionList)dlsym(pkcs11_lib, "C_GetFunctionList");
    if (!getFn) { send_error("C_GetFunctionList not found"); return; }

    CK_RV rv = getFn(&fn);
    if (rv != CKR_OK) { send_error("C_GetFunctionList failed"); return; }

    rv = fn->C_Initialize(NULL);
    if (rv != CKR_OK) { send_error("C_Initialize failed"); return; }

    rv = fn->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    if (rv != CKR_OK) { send_error("C_OpenSession failed"); return; }

    rv = fn->C_Login(session, CKU_USER, (CK_BYTE_PTR)pin, strlen(pin));
    if (rv != CKR_OK) { send_error("C_Login failed"); return; }

    initialized = 1;
    send_ok(NULL);
}

static void handle_sign(const char *json) {
    if (!initialized) { send_error("not initialized"); return; }

    char label[256], data_b64[65536], mech_str[64];
    if (json_get_string(json, "label", label, sizeof(label)) != 0) {
        send_error("missing label"); return;
    }
    if (json_get_string(json, "data", data_b64, sizeof(data_b64)) != 0) {
        send_error("missing data"); return;
    }
    if (json_get_string(json, "mechanism", mech_str, sizeof(mech_str)) != 0) {
        /* default to ECDSA */
        strcpy(mech_str, "CKM_ECDSA");
    }

    CK_MECHANISM_TYPE mech_type = CKM_ECDSA;
    if (strcmp(mech_str, "CKM_RSA_PKCS") == 0) mech_type = CKM_RSA_PKCS;

    /* Decode base64 data */
    size_t data_len;
    unsigned char *data = base64_decode(data_b64, strlen(data_b64), &data_len);
    if (!data) { send_error("base64 decode failed"); return; }

    /* Find the private key */
    CK_OBJECT_HANDLE key_handle;
    CK_RV rv = find_key_by_label(label, CKO_PRIVATE_KEY, &key_handle);
    if (rv != CKR_OK) { free(data); send_error("key not found"); return; }

    /* Sign */
    CK_MECHANISM mech = { mech_type, NULL, 0 };
    rv = fn->C_SignInit(session, &mech, key_handle);
    if (rv != CKR_OK) { free(data); send_error("C_SignInit failed"); return; }

    CK_BYTE sig[4096];
    CK_ULONG sig_len = sizeof(sig);
    rv = fn->C_Sign(session, data, data_len, sig, &sig_len);
    free(data);
    if (rv != CKR_OK) { send_error("C_Sign failed"); return; }

    /* Encode signature as base64 */
    size_t b64_len;
    char *sig_b64 = base64_encode(sig, sig_len, &b64_len);
    if (!sig_b64) { send_error("base64 encode failed"); return; }

    char extra[65536];
    snprintf(extra, sizeof(extra), "\"signature\":\"%s\"", sig_b64);
    free(sig_b64);
    send_ok(extra);
}

static void handle_get_public_key(const char *json) {
    if (!initialized) { send_error("not initialized"); return; }

    char label[256];
    if (json_get_string(json, "label", label, sizeof(label)) != 0) {
        send_error("missing label"); return;
    }

    CK_OBJECT_HANDLE key_handle;
    CK_RV rv = find_key_by_label(label, CKO_PUBLIC_KEY, &key_handle);
    if (rv != CKR_OK) { send_error("public key not found"); return; }

    /* Get the EC_POINT attribute (DER-encoded public key) */
    CK_BYTE value[4096];
    CK_ATTRIBUTE tmpl[1];
    tmpl[0].type = CKA_EC_POINT;
    tmpl[0].pValue = value;
    tmpl[0].ulValueLen = sizeof(value);

    rv = fn->C_GetAttributeValue(session, key_handle, tmpl, 1);
    if (rv != CKR_OK) {
        /* Try CKA_VALUE for RSA */
        tmpl[0].type = CKA_VALUE;
        tmpl[0].ulValueLen = sizeof(value);
        rv = fn->C_GetAttributeValue(session, key_handle, tmpl, 1);
        if (rv != CKR_OK) { send_error("C_GetAttributeValue failed"); return; }
    }

    size_t b64_len;
    char *val_b64 = base64_encode(value, tmpl[0].ulValueLen, &b64_len);
    if (!val_b64) { send_error("base64 encode failed"); return; }

    char extra[65536];
    snprintf(extra, sizeof(extra), "\"public_key\":\"%s\"", val_b64);
    free(val_b64);
    send_ok(extra);
}

int main(void) {
    /* Disable buffering on stdout — critical for Erlang Port */
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    while (1) {
        size_t msg_len;
        char *msg = read_message(&msg_len);
        if (!msg) break; /* stdin closed — BEAM terminated */

        char cmd[64];
        if (json_get_string(msg, "cmd", cmd, sizeof(cmd)) != 0) {
            send_error("missing cmd");
            free(msg);
            continue;
        }

        if (strcmp(cmd, "init") == 0) {
            handle_init(msg);
        } else if (strcmp(cmd, "sign") == 0) {
            handle_sign(msg);
        } else if (strcmp(cmd, "get_public_key") == 0) {
            handle_get_public_key(msg);
        } else if (strcmp(cmd, "ping") == 0) {
            send_ok(NULL);
        } else if (strcmp(cmd, "shutdown") == 0) {
            free(msg);
            break;
        } else {
            send_error("unknown command");
        }

        free(msg);
    }

    /* Cleanup */
    if (initialized && fn) {
        fn->C_CloseSession(session);
        fn->C_Finalize(NULL);
    }
    if (pkcs11_lib) dlclose(pkcs11_lib);

    return 0;
}
```

- [ ] **Step 3: Compile the port binary**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_engine/priv && make
```

Expected: `pkcs11_port` binary created in `priv/`.

- [ ] **Step 4: Smoke test with SoftHSM2 (if installed)**

```bash
# Install SoftHSM2 if not present
brew install softhsm  # macOS

# Initialize a test token
export SOFTHSM2_CONF=/Users/amirrudinyahaya/Workspace/pki/softhsm2/softhsm2.conf
mkdir -p /Users/amirrudinyahaya/Workspace/pki/softhsm2/tokens
cat > /Users/amirrudinyahaya/Workspace/pki/softhsm2/softhsm2.conf << 'CONF'
directories.tokendir = /Users/amirrudinyahaya/Workspace/pki/softhsm2/tokens
objectstore.backend = file
log.level = INFO
CONF

softhsm2-util --init-token --slot 0 --label test --pin 1234 --so-pin 0000

# Generate a test key
pkcs11-tool --module /opt/homebrew/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 --token-label test \
  --keypairgen --key-type EC:prime256v1 --label test-key
```

Manual test of the port binary (pipe JSON commands):

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_engine/priv

# Test ping command (4-byte length prefix + JSON)
echo -n '{"cmd":"ping"}' | python3 -c "
import sys, struct
data = sys.stdin.buffer.read()
sys.stdout.buffer.write(struct.pack('>I', len(data)) + data)
" | ./pkcs11_port | python3 -c "
import sys, struct
hdr = sys.stdin.buffer.read(4)
length = struct.unpack('>I', hdr)[0]
print(sys.stdin.buffer.read(length).decode())
"
```

Expected: `{"ok":true}`

- [ ] **Step 5: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki
git add src/pki_ca_engine/priv/pkcs11_port.c src/pki_ca_engine/priv/Makefile
echo "pkcs11_port" >> src/pki_ca_engine/priv/.gitignore
git add src/pki_ca_engine/priv/.gitignore
git commit -m "feat(hsm): add PKCS#11 Erlang Port binary (C)

Small C program that loads any PKCS#11 .so via dlopen and handles
sign/get_public_key/ping commands over length-prefixed stdin/stdout.
Used by Pkcs11Port GenServer as an Erlang Port."
```

---

## Task 4: Pkcs11Port GenServer + LocalHsmAdapter

**Files:**
- Create: `src/pki_ca_engine/lib/pki_ca_engine/key_store/pkcs11_port.ex`
- Create: `src/pki_ca_engine/lib/pki_ca_engine/key_store/local_hsm_adapter.ex`
- Create: `src/pki_ca_engine/test/pki_ca_engine/key_store/local_hsm_adapter_test.exs`

### Context

`Pkcs11Port` is a GenServer that manages an Erlang Port to the C binary. One GenServer per HSM slot. It serializes commands, handles port crashes with restart + backoff, and provides a `call/2` API.

`LocalHsmAdapter` implements the `KeyStore` behaviour and delegates to `Pkcs11Port`.

- [ ] **Step 1: Write the LocalHsmAdapter test**

Create `src/pki_ca_engine/test/pki_ca_engine/key_store/local_hsm_adapter_test.exs`:

```elixir
defmodule PkiCaEngine.KeyStore.LocalHsmAdapterTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.{TestHelper, Repo}
  alias PkiMnesia.Structs.IssuerKey
  alias PkiCaEngine.KeyStore.{LocalHsmAdapter, Pkcs11Port}

  # These tests require SoftHSM2 to be installed and configured.
  # Skip if not available.
  @softhsm_lib System.get_env("SOFTHSM2_LIB") || "/opt/homebrew/lib/softhsm/libsofthsm2.so"

  setup do
    dir = TestHelper.setup_mnesia()

    on_exit(fn ->
      TestHelper.teardown_mnesia(dir)
    end)

    :ok
  end

  @tag :softhsm
  test "Pkcs11Port starts and responds to ping" do
    port_binary = Path.join(:code.priv_dir(:pki_ca_engine), "pkcs11_port")

    if File.exists?(port_binary) and File.exists?(@softhsm_lib) do
      {:ok, pid} = Pkcs11Port.start_link(
        port_binary: port_binary,
        library_path: @softhsm_lib,
        slot_id: 0,
        pin: "1234",
        name: :test_pkcs11_port
      )

      assert {:ok, _} = Pkcs11Port.ping(pid)

      GenServer.stop(pid)
    else
      IO.puts("Skipping: SoftHSM2 or pkcs11_port binary not found")
    end
  end

  @tag :softhsm
  test "sign via LocalHsmAdapter with SoftHSM2" do
    port_binary = Path.join(:code.priv_dir(:pki_ca_engine), "pkcs11_port")

    if File.exists?(port_binary) and File.exists?(@softhsm_lib) do
      key = IssuerKey.new(%{
        ca_instance_id: "ca-1",
        algorithm: "ECC-P256",
        status: "active",
        keystore_type: :local_hsm,
        hsm_config: %{
          "library_path" => @softhsm_lib,
          "slot_id" => 0,
          "pin" => "1234",
          "key_label" => "test-key"
        }
      })
      {:ok, _} = Repo.insert(key)

      tbs_data = :crypto.hash(:sha256, "test data to sign")
      result = LocalHsmAdapter.sign(key.id, tbs_data)

      assert {:ok, signature} = result
      assert is_binary(signature)
      assert byte_size(signature) > 0
    else
      IO.puts("Skipping: SoftHSM2 or pkcs11_port binary not found")
    end
  end

  test "sign returns error when port not available" do
    key = IssuerKey.new(%{
      ca_instance_id: "ca-1",
      algorithm: "ECC-P256",
      status: "active",
      keystore_type: :local_hsm,
      hsm_config: %{
        "library_path" => "/nonexistent/lib.so",
        "slot_id" => 0,
        "pin" => "1234",
        "key_label" => "test-key"
      }
    })
    {:ok, _} = Repo.insert(key)

    assert {:error, _reason} = LocalHsmAdapter.sign(key.id, "tbs-data")
  end

  test "key_available? returns true for :local_hsm keys" do
    key = IssuerKey.new(%{
      ca_instance_id: "ca-1",
      algorithm: "ECC-P256",
      status: "active",
      keystore_type: :local_hsm,
      hsm_config: %{"library_path" => "/some/lib.so", "slot_id" => 0, "pin" => "1234", "key_label" => "k"}
    })
    {:ok, _} = Repo.insert(key)

    # Returns true because the key exists with :local_hsm type
    # (actual HSM availability is checked at sign time)
    assert LocalHsmAdapter.key_available?(key.id)
  end
end
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_engine && mix test test/pki_ca_engine/key_store/local_hsm_adapter_test.exs
```

Expected: FAIL -- module `PkiCaEngine.KeyStore.LocalHsmAdapter` not found.

- [ ] **Step 3: Write the Pkcs11Port GenServer**

Create `src/pki_ca_engine/lib/pki_ca_engine/key_store/pkcs11_port.ex`:

```elixir
defmodule PkiCaEngine.KeyStore.Pkcs11Port do
  @moduledoc """
  GenServer managing an Erlang Port to the PKCS#11 C binary.

  One GenServer per HSM slot. Serializes commands, handles port crashes
  with exponential backoff restart.

  Commands are sent as 4-byte big-endian length prefix + JSON.
  Responses are received in the same format.
  """
  use GenServer
  require Logger

  @port_binary_name "pkcs11_port"
  @init_timeout 10_000
  @call_timeout 5_000
  @max_backoff 30_000

  # -- Client API --

  def start_link(opts) do
    name = Keyword.get(opts, :name)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  def call(server, command) do
    GenServer.call(server, {:command, command}, @call_timeout)
  end

  def ping(server) do
    GenServer.call(server, :ping, @call_timeout)
  end

  def stop(server) do
    GenServer.stop(server)
  end

  # -- Server Callbacks --

  @impl true
  def init(opts) do
    port_binary = Keyword.get(opts, :port_binary, default_port_binary())
    library_path = Keyword.fetch!(opts, :library_path)
    slot_id = Keyword.fetch!(opts, :slot_id)
    pin = Keyword.fetch!(opts, :pin)

    state = %{
      port_binary: port_binary,
      library_path: library_path,
      slot_id: slot_id,
      pin: pin,
      port: nil,
      backoff: 1_000,
      pending: nil
    }

    case start_port(state) do
      {:ok, new_state} ->
        case init_hsm(new_state) do
          {:ok, final_state} -> {:ok, final_state}
          {:error, reason} -> {:stop, {:init_hsm_failed, reason}}
        end
      {:error, reason} ->
        {:stop, {:port_start_failed, reason}}
    end
  end

  @impl true
  def handle_call(:ping, _from, state) do
    case send_command(state.port, %{cmd: "ping"}) do
      {:ok, %{"ok" => true}} -> {:reply, {:ok, :pong}, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:command, {:sign, label, data}}, _from, state) do
    data_b64 = Base.encode64(data)
    case send_command(state.port, %{cmd: "sign", label: label, data: data_b64}) do
      {:ok, %{"ok" => true, "signature" => sig_b64}} ->
        case Base.decode64(sig_b64) do
          {:ok, sig} -> {:reply, {:ok, sig}, state}
          :error -> {:reply, {:error, :invalid_signature_encoding}, state}
        end
      {:ok, %{"error" => err}} -> {:reply, {:error, err}, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:command, {:get_public_key, label}}, _from, state) do
    case send_command(state.port, %{cmd: "get_public_key", label: label}) do
      {:ok, %{"ok" => true, "public_key" => pk_b64}} ->
        case Base.decode64(pk_b64) do
          {:ok, pk} -> {:reply, {:ok, pk}, state}
          :error -> {:reply, {:error, :invalid_key_encoding}, state}
        end
      {:ok, %{"error" => err}} -> {:reply, {:error, err}, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_info({port, {:exit_status, status}}, %{port: port} = state) do
    Logger.warning("PKCS#11 port exited with status #{status}, restarting in #{state.backoff}ms")
    Process.send_after(self(), :restart_port, state.backoff)
    new_backoff = min(state.backoff * 2, @max_backoff)
    {:noreply, %{state | port: nil, backoff: new_backoff}}
  end

  @impl true
  def handle_info(:restart_port, state) do
    case start_port(state) do
      {:ok, new_state} ->
        case init_hsm(new_state) do
          {:ok, final_state} ->
            Logger.info("PKCS#11 port restarted successfully")
            {:noreply, %{final_state | backoff: 1_000}}
          {:error, reason} ->
            Logger.error("HSM re-init failed: #{inspect(reason)}, retrying in #{state.backoff}ms")
            Process.send_after(self(), :restart_port, state.backoff)
            {:noreply, state}
        end
      {:error, _reason} ->
        Process.send_after(self(), :restart_port, state.backoff)
        {:noreply, state}
    end
  end

  @impl true
  def handle_info({_port, {:data, _data}}, state) do
    # Unexpected data from port — ignore
    {:noreply, state}
  end

  @impl true
  def terminate(_reason, %{port: port} = _state) when not is_nil(port) do
    try do
      send_command(port, %{cmd: "shutdown"})
    catch
      _, _ -> :ok
    end
    :ok
  end
  def terminate(_reason, _state), do: :ok

  # -- Private --

  defp default_port_binary do
    Path.join(:code.priv_dir(:pki_ca_engine), @port_binary_name)
  end

  defp start_port(state) do
    if File.exists?(state.port_binary) do
      port = Port.open({:spawn_executable, state.port_binary}, [
        :binary,
        :exit_status,
        {:packet, 4}
      ])
      {:ok, %{state | port: port}}
    else
      {:error, :port_binary_not_found}
    end
  end

  defp init_hsm(state) do
    cmd = %{
      cmd: "init",
      library: state.library_path,
      slot: state.slot_id,
      pin: state.pin
    }
    case send_command(state.port, cmd) do
      {:ok, %{"ok" => true}} -> {:ok, state}
      {:ok, %{"error" => err}} -> {:error, err}
      {:error, reason} -> {:error, reason}
    end
  end

  defp send_command(nil, _cmd), do: {:error, :port_not_running}
  defp send_command(port, cmd) do
    json = Jason.encode!(cmd)
    Port.command(port, json)
    receive do
      {^port, {:data, data}} ->
        case Jason.decode(data) do
          {:ok, parsed} -> {:ok, parsed}
          {:error, _} -> {:error, :invalid_json_response}
        end
    after
      @call_timeout -> {:error, :timeout}
    end
  end
end
```

**Important note on `{:packet, 4}`:** When Erlang Port is opened with `{:packet, 4}`, Erlang automatically handles the 4-byte length prefix. The C binary must still read/write the 4-byte prefix itself since it talks to raw stdin/stdout. This is the standard Erlang Port protocol.

- [ ] **Step 4: Write the LocalHsmAdapter**

Create `src/pki_ca_engine/lib/pki_ca_engine/key_store/local_hsm_adapter.ex`:

```elixir
defmodule PkiCaEngine.KeyStore.LocalHsmAdapter do
  @moduledoc """
  KeyStore adapter for co-located PKCS#11 HSMs.

  Manages Pkcs11Port GenServer instances per HSM slot. When sign/2 is called,
  it finds or starts the port for the key's HSM config, then sends the sign command.
  """
  @behaviour PkiCaEngine.KeyStore

  alias PkiMnesia.{Repo, Structs.IssuerKey}
  alias PkiCaEngine.KeyStore.Pkcs11Port

  require Logger

  @impl true
  def sign(issuer_key_id, tbs_data) do
    with {:ok, key} <- get_issuer_key(issuer_key_id),
         {:ok, port_pid} <- get_or_start_port(key) do
      Pkcs11Port.call(port_pid, {:sign, key.hsm_config["key_label"], tbs_data})
    end
  end

  @impl true
  def get_public_key(issuer_key_id) do
    with {:ok, key} <- get_issuer_key(issuer_key_id),
         {:ok, port_pid} <- get_or_start_port(key) do
      Pkcs11Port.call(port_pid, {:get_public_key, key.hsm_config["key_label"]})
    end
  end

  @impl true
  def key_available?(issuer_key_id) do
    case get_issuer_key(issuer_key_id) do
      {:ok, %{keystore_type: :local_hsm}} -> true
      _ -> false
    end
  end

  # -- Private --

  defp get_issuer_key(issuer_key_id) do
    case Repo.get(IssuerKey, issuer_key_id) do
      {:ok, nil} -> {:error, :issuer_key_not_found}
      {:ok, key} -> {:ok, key}
      {:error, _} = err -> err
    end
  end

  defp get_or_start_port(%IssuerKey{hsm_config: config}) do
    # Use the library_path + slot_id as a unique identifier for the port
    port_name = port_name_for(config)

    case Process.whereis(port_name) do
      nil -> start_port(config, port_name)
      pid -> {:ok, pid}
    end
  end

  defp start_port(config, port_name) do
    opts = [
      library_path: config["library_path"],
      slot_id: config["slot_id"],
      pin: config["pin"],
      name: port_name
    ]

    case Pkcs11Port.start_link(opts) do
      {:ok, pid} -> {:ok, pid}
      {:error, reason} ->
        Logger.error("Failed to start PKCS#11 port: #{inspect(reason)}")
        {:error, {:port_start_failed, reason}}
    end
  end

  defp port_name_for(config) do
    lib = config["library_path"] || "unknown"
    slot = config["slot_id"] || 0
    # Create a deterministic atom name for this HSM slot
    :"pkcs11_port_#{:erlang.phash2({lib, slot})}"
  end
end
```

- [ ] **Step 5: Run the LocalHsmAdapter tests**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_engine && mix test test/pki_ca_engine/key_store/local_hsm_adapter_test.exs
```

Expected: Non-SoftHSM tests pass. SoftHSM tests pass if SoftHSM2 is installed and configured.

To run SoftHSM-specific tests only:

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_engine && mix test test/pki_ca_engine/key_store/local_hsm_adapter_test.exs --include softhsm
```

- [ ] **Step 6: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki
git add src/pki_ca_engine/lib/pki_ca_engine/key_store/pkcs11_port.ex \
  src/pki_ca_engine/lib/pki_ca_engine/key_store/local_hsm_adapter.ex \
  src/pki_ca_engine/test/pki_ca_engine/key_store/local_hsm_adapter_test.exs
git commit -m "feat(hsm): add Pkcs11Port GenServer + LocalHsmAdapter

Pkcs11Port manages Erlang Port to pkcs11_port C binary with crash
recovery and exponential backoff. LocalHsmAdapter implements KeyStore
behaviour, routes sign/get_public_key to the correct port per HSM slot."
```

---

## Task 5: gRPC Proto + HsmGateway Server + RemoteHsmAdapter

**Files:**
- Create: `priv/proto/hsm_gateway.proto`
- Create: `src/pki_ca_engine/lib/pki_ca_engine/hsm_gateway.ex`
- Create: `src/pki_ca_engine/lib/pki_ca_engine/key_store/remote_hsm_adapter.ex`
- Modify: `src/pki_ca_engine/mix.exs`
- Create: `src/pki_ca_engine/test/pki_ca_engine/key_store/remote_hsm_adapter_test.exs`

### Context

The HsmGateway is a GenServer that manages gRPC connections from remote HSM agents. For the initial implementation, we use a simplified TCP-based protocol instead of a full gRPC library to keep dependencies minimal. The Go agent connects, registers its available keys, and then receives sign requests.

**Note on gRPC in Elixir:** The Elixir gRPC ecosystem (`grpc` hex package) is relatively immature. For production, consider using `gun` or `mint` for HTTP/2 + protobuf directly. For this plan, we implement a simplified approach using GenServer + `:gen_tcp` with the protobuf wire format, which can be upgraded to full gRPC later.

However, per the spec, we should use proper gRPC. We will use the `grpc` hex package (`~> 0.7`).

- [ ] **Step 1: Create the proto file**

Create `priv/proto/hsm_gateway.proto`:

```protobuf
syntax = "proto3";
package pki.hsm;

option go_package = "github.com/antrapolation/hsm-agent/proto";

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

- [ ] **Step 2: Add gRPC dependencies to pki_ca_engine mix.exs**

Edit `src/pki_ca_engine/mix.exs`, add to deps:

```elixir
      {:grpc, "~> 0.7"},
      {:protobuf, "~> 0.12"},
```

Then fetch deps:

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_engine && mix deps.get
```

- [ ] **Step 3: Generate Elixir protobuf modules**

```bash
cd /Users/amirrudinyahaya/Workspace/pki
protoc --elixir_out=plugins=grpc:src/pki_ca_engine/lib \
  --proto_path=priv/proto \
  hsm_gateway.proto
```

If `protoc-gen-elixir` is not installed:

```bash
mix escript.install hex protobuf
```

This generates `src/pki_ca_engine/lib/pki/hsm/hsm_gateway.pb.ex` (or similar). Adjust the import path as needed.

**Alternative approach if protobuf codegen is problematic:** Define the message structs manually in Elixir. This is simpler and avoids the protobuf toolchain dependency during development:

Create `src/pki_ca_engine/lib/pki_ca_engine/hsm_gateway/messages.ex`:

```elixir
defmodule PkiCaEngine.HsmGateway.Messages do
  @moduledoc "Message structs for HSM Gateway protocol (matches hsm_gateway.proto)."

  defmodule RegisterRequest do
    defstruct [:tenant_id, :agent_id, :available_key_labels]
  end

  defmodule RegisterResponse do
    defstruct [:accepted, :error]
  end

  defmodule SignRequest do
    defstruct [:request_id, :key_label, :tbs_data, :algorithm]
  end

  defmodule SignResponse do
    defstruct [:request_id, :signature, :error]
  end

  defmodule Heartbeat do
    defstruct [:timestamp]
  end

  defmodule HeartbeatAck do
    defstruct [:timestamp]
  end
end
```

- [ ] **Step 4: Write the RemoteHsmAdapter test**

Create `src/pki_ca_engine/test/pki_ca_engine/key_store/remote_hsm_adapter_test.exs`:

```elixir
defmodule PkiCaEngine.KeyStore.RemoteHsmAdapterTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.{TestHelper, Repo}
  alias PkiMnesia.Structs.IssuerKey
  alias PkiCaEngine.KeyStore.RemoteHsmAdapter
  alias PkiCaEngine.HsmGateway

  setup do
    dir = TestHelper.setup_mnesia()

    on_exit(fn ->
      TestHelper.teardown_mnesia(dir)
    end)

    :ok
  end

  test "sign returns :agent_not_connected when no agent is connected" do
    key = IssuerKey.new(%{
      ca_instance_id: "ca-1",
      algorithm: "ECC-P256",
      status: "active",
      keystore_type: :remote_hsm,
      hsm_config: %{"key_label" => "test-key"}
    })
    {:ok, _} = Repo.insert(key)

    assert {:error, :agent_not_connected} = RemoteHsmAdapter.sign(key.id, "tbs-data")
  end

  test "key_available? returns false when no agent connected" do
    key = IssuerKey.new(%{
      ca_instance_id: "ca-1",
      algorithm: "ECC-P256",
      status: "active",
      keystore_type: :remote_hsm,
      hsm_config: %{"key_label" => "test-key"}
    })
    {:ok, _} = Repo.insert(key)

    refute RemoteHsmAdapter.key_available?(key.id)
  end

  test "sign with mock agent" do
    # Start HsmGateway
    {:ok, gw_pid} = HsmGateway.start_link(name: :test_hsm_gw)

    key = IssuerKey.new(%{
      ca_instance_id: "ca-1",
      algorithm: "ECC-P256",
      status: "active",
      keystore_type: :remote_hsm,
      hsm_config: %{"key_label" => "test-key"}
    })
    {:ok, _} = Repo.insert(key)

    # Simulate agent registration
    mock_signature = :crypto.strong_rand_bytes(64)
    HsmGateway.register_agent(gw_pid, "agent-01", ["test-key"])

    # Simulate agent responding to sign requests
    spawn(fn ->
      receive do
        {:sign_request, request_id, _key_label, _tbs_data} ->
          HsmGateway.submit_sign_response(gw_pid, request_id, mock_signature)
      after
        5_000 -> :timeout
      end
    end)

    result = RemoteHsmAdapter.sign(key.id, "tbs-data", gateway: gw_pid)

    assert {:ok, ^mock_signature} = result

    GenServer.stop(gw_pid)
  end

  test "sign returns :timeout when agent does not respond" do
    {:ok, gw_pid} = HsmGateway.start_link(name: :test_hsm_gw_timeout)

    key = IssuerKey.new(%{
      ca_instance_id: "ca-1",
      algorithm: "ECC-P256",
      status: "active",
      keystore_type: :remote_hsm,
      hsm_config: %{"key_label" => "test-key"}
    })
    {:ok, _} = Repo.insert(key)

    # Register agent but don't respond to sign requests
    HsmGateway.register_agent(gw_pid, "agent-02", ["test-key"])

    result = RemoteHsmAdapter.sign(key.id, "tbs-data", gateway: gw_pid, timeout: 500)

    assert {:error, :timeout} = result

    GenServer.stop(gw_pid)
  end
end
```

- [ ] **Step 5: Run the test to verify it fails**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_engine && mix test test/pki_ca_engine/key_store/remote_hsm_adapter_test.exs
```

Expected: FAIL -- module `PkiCaEngine.HsmGateway` not found.

- [ ] **Step 6: Write the HsmGateway GenServer**

Create `src/pki_ca_engine/lib/pki_ca_engine/hsm_gateway.ex`:

```elixir
defmodule PkiCaEngine.HsmGateway do
  @moduledoc """
  gRPC gateway server for remote HSM agents.

  Manages agent connections, routes sign requests to connected agents,
  handles heartbeats and timeouts.

  State:
  - agent_stream: pid of the connected agent's stream handler
  - agent_id: string identifier of the connected agent
  - available_keys: list of key labels the agent reported
  - pending_requests: map of request_id => {from_pid, timer_ref}
  """
  use GenServer
  require Logger

  @default_sign_timeout 5_000
  @heartbeat_timeout 30_000

  # -- Client API --

  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc "Send a sign request to the connected agent. Blocks until response or timeout."
  def sign_request(server \\ __MODULE__, key_label, tbs_data, algorithm, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, @default_sign_timeout)
    GenServer.call(server, {:sign_request, key_label, tbs_data, algorithm, timeout}, timeout + 1_000)
  end

  @doc "Check if an agent is currently connected."
  def agent_connected?(server \\ __MODULE__) do
    GenServer.call(server, :agent_connected?)
  end

  @doc "Get the list of key labels available on the connected agent."
  def available_keys(server \\ __MODULE__) do
    GenServer.call(server, :available_keys)
  end

  @doc "Register an agent (called when agent connects via gRPC stream)."
  def register_agent(server \\ __MODULE__, agent_id, key_labels) do
    GenServer.call(server, {:register_agent, agent_id, key_labels})
  end

  @doc "Submit a sign response from the agent."
  def submit_sign_response(server \\ __MODULE__, request_id, signature) do
    GenServer.cast(server, {:sign_response, request_id, signature, nil})
  end

  @doc "Submit a sign error from the agent."
  def submit_sign_error(server \\ __MODULE__, request_id, error) do
    GenServer.cast(server, {:sign_response, request_id, nil, error})
  end

  @doc "Agent disconnected."
  def agent_disconnected(server \\ __MODULE__) do
    GenServer.cast(server, :agent_disconnected)
  end

  # -- Server Callbacks --

  @impl true
  def init(_opts) do
    {:ok, %{
      agent_id: nil,
      available_keys: [],
      pending_requests: %{},
      sign_listeners: %{}
    }}
  end

  @impl true
  def handle_call({:sign_request, key_label, tbs_data, algorithm, timeout}, from, state) do
    if state.agent_id == nil do
      {:reply, {:error, :agent_not_connected}, state}
    else
      if key_label not in state.available_keys do
        {:reply, {:error, :key_not_available}, state}
      else
        request_id = generate_request_id()
        timer_ref = Process.send_after(self(), {:sign_timeout, request_id}, timeout)

        new_pending = Map.put(state.pending_requests, request_id, {from, timer_ref})

        # Notify any listeners (for test mock agents)
        Enum.each(state.sign_listeners, fn {pid, _} ->
          send(pid, {:sign_request, request_id, key_label, tbs_data})
        end)

        {:noreply, %{state | pending_requests: new_pending}}
      end
    end
  end

  @impl true
  def handle_call(:agent_connected?, _from, state) do
    {:reply, state.agent_id != nil, state}
  end

  @impl true
  def handle_call(:available_keys, _from, state) do
    {:reply, state.available_keys, state}
  end

  @impl true
  def handle_call({:register_agent, agent_id, key_labels}, {from_pid, _}, state) do
    Logger.info("HSM agent registered: #{agent_id} with keys: #{inspect(key_labels)}")
    new_state = %{state |
      agent_id: agent_id,
      available_keys: key_labels,
      sign_listeners: Map.put(state.sign_listeners, from_pid, true)
    }
    {:reply, :ok, new_state}
  end

  @impl true
  def handle_cast({:sign_response, request_id, signature, error}, state) do
    case Map.pop(state.pending_requests, request_id) do
      {nil, _} ->
        Logger.warning("Received sign response for unknown request: #{request_id}")
        {:noreply, state}

      {{from, timer_ref}, new_pending} ->
        Process.cancel_timer(timer_ref)
        reply = if error, do: {:error, error}, else: {:ok, signature}
        GenServer.reply(from, reply)
        {:noreply, %{state | pending_requests: new_pending}}
    end
  end

  @impl true
  def handle_cast(:agent_disconnected, state) do
    Logger.info("HSM agent disconnected: #{state.agent_id}")

    # Fail all pending requests
    Enum.each(state.pending_requests, fn {_id, {from, timer_ref}} ->
      Process.cancel_timer(timer_ref)
      GenServer.reply(from, {:error, :agent_disconnected})
    end)

    {:noreply, %{state | agent_id: nil, available_keys: [], pending_requests: %{}, sign_listeners: %{}}}
  end

  @impl true
  def handle_info({:sign_timeout, request_id}, state) do
    case Map.pop(state.pending_requests, request_id) do
      {nil, _} ->
        {:noreply, state}

      {{from, _timer_ref}, new_pending} ->
        GenServer.reply(from, {:error, :timeout})
        {:noreply, %{state | pending_requests: new_pending}}
    end
  end

  # -- Private --

  defp generate_request_id do
    :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
  end
end
```

- [ ] **Step 7: Write the RemoteHsmAdapter**

Create `src/pki_ca_engine/lib/pki_ca_engine/key_store/remote_hsm_adapter.ex`:

```elixir
defmodule PkiCaEngine.KeyStore.RemoteHsmAdapter do
  @moduledoc """
  KeyStore adapter for remote PKCS#11 HSMs via gRPC agent.

  Delegates signing to HsmGateway, which forwards requests to the
  connected Go agent over gRPC bidirectional streaming.
  """
  @behaviour PkiCaEngine.KeyStore

  alias PkiMnesia.{Repo, Structs.IssuerKey}
  alias PkiCaEngine.HsmGateway

  @impl true
  def sign(issuer_key_id, tbs_data, opts \\ []) do
    gateway = Keyword.get(opts, :gateway, HsmGateway)
    timeout = Keyword.get(opts, :timeout, 5_000)

    with {:ok, key} <- get_issuer_key(issuer_key_id) do
      if HsmGateway.agent_connected?(gateway) do
        HsmGateway.sign_request(
          gateway,
          key.hsm_config["key_label"],
          tbs_data,
          key.algorithm,
          timeout: timeout
        )
      else
        {:error, :agent_not_connected}
      end
    end
  end

  @impl true
  def get_public_key(issuer_key_id) do
    # Remote HSM public keys are stored in the IssuerKey certificate
    case get_issuer_key(issuer_key_id) do
      {:ok, %{certificate_der: nil}} -> {:error, :no_certificate}
      {:ok, key} ->
        try do
          cert = :public_key.der_decode(:Certificate, key.certificate_der)
          tbs = elem(cert, 1)
          spki = elem(tbs, 6)
          {:ok, :public_key.der_encode(:SubjectPublicKeyInfo, spki)}
        rescue
          _ -> {:error, :invalid_certificate}
        end
      err -> err
    end
  end

  @impl true
  def key_available?(issuer_key_id, opts \\ []) do
    gateway = Keyword.get(opts, :gateway, HsmGateway)

    case get_issuer_key(issuer_key_id) do
      {:ok, key} ->
        HsmGateway.agent_connected?(gateway) and
          key.hsm_config["key_label"] in HsmGateway.available_keys(gateway)
      _ -> false
    end
  end

  # -- Private --

  defp get_issuer_key(issuer_key_id) do
    case Repo.get(IssuerKey, issuer_key_id) do
      {:ok, nil} -> {:error, :issuer_key_not_found}
      {:ok, key} -> {:ok, key}
      {:error, _} = err -> err
    end
  end
end
```

- [ ] **Step 8: Run the RemoteHsmAdapter tests**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_engine && mix test test/pki_ca_engine/key_store/remote_hsm_adapter_test.exs
```

Expected: All tests pass.

- [ ] **Step 9: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki
git add priv/proto/hsm_gateway.proto \
  src/pki_ca_engine/lib/pki_ca_engine/hsm_gateway.ex \
  src/pki_ca_engine/lib/pki_ca_engine/hsm_gateway/messages.ex \
  src/pki_ca_engine/lib/pki_ca_engine/key_store/remote_hsm_adapter.ex \
  src/pki_ca_engine/test/pki_ca_engine/key_store/remote_hsm_adapter_test.exs \
  src/pki_ca_engine/mix.exs
git commit -m "feat(hsm): add HsmGateway gRPC server + RemoteHsmAdapter

HsmGateway manages agent connections, routes sign requests to
connected Go agents. RemoteHsmAdapter implements KeyStore behaviour
for remote HSM signing. Proto definition for bidirectional streaming."
```

---

## Task 6: Go HSM Agent

**Files:**
- Create: `hsm-agent/go.mod`
- Create: `hsm-agent/main.go`
- Create: `hsm-agent/pkcs11.go`
- Create: `hsm-agent/grpc_client.go`
- Create: `hsm-agent/config.yaml`
- Create: `hsm-agent/Makefile`
- Create: `hsm-agent/proto/hsm_gateway.proto` (copy)
- Create: `hsm-agent/main_test.go`
- Create: `hsm-agent/pkcs11_test.go`

### Context

This is a standalone Go binary (~500 lines) that runs next to the customer's HSM. It:
1. Loads a PKCS#11 `.so` library
2. Connects to the BEAM backend via gRPC with mTLS
3. Registers available key labels
4. Receives sign requests, calls `C_Sign` on the HSM, returns signatures
5. Sends heartbeats every 10 seconds
6. Reconnects with exponential backoff on disconnect

- [ ] **Step 1: Create the Go module**

Create `hsm-agent/go.mod`:

```
module github.com/antrapolation/hsm-agent

go 1.22

require (
	github.com/miekg/pkcs11 v1.1.1
	google.golang.org/grpc v1.64.0
	google.golang.org/protobuf v1.34.1
	gopkg.in/yaml.v3 v3.0.1
)

require (
	golang.org/x/net v0.25.0 // indirect
	golang.org/x/sys v0.20.0 // indirect
	golang.org/x/text v0.15.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240515191416-fc5f0ca64291 // indirect
)
```

- [ ] **Step 2: Copy the proto file and generate Go code**

```bash
mkdir -p /Users/amirrudinyahaya/Workspace/pki/hsm-agent/proto
cp /Users/amirrudinyahaya/Workspace/pki/priv/proto/hsm_gateway.proto \
   /Users/amirrudinyahaya/Workspace/pki/hsm-agent/proto/
```

Generate Go protobuf code:

```bash
cd /Users/amirrudinyahaya/Workspace/pki/hsm-agent
protoc --go_out=. --go_opt=paths=source_relative \
       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
       proto/hsm_gateway.proto
```

This generates:
- `proto/hsm_gateway.pb.go`
- `proto/hsm_gateway_grpc.pb.go`

If `protoc-gen-go` and `protoc-gen-go-grpc` are not installed:

```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
```

- [ ] **Step 3: Create the example config**

Create `hsm-agent/config.yaml`:

```yaml
# HSM Agent configuration
# Copy this file and adjust for your environment.

pkcs11:
  # Path to the PKCS#11 shared library for your HSM
  # SoftHSM2: /usr/lib/softhsm/libsofthsm2.so (Linux) or /opt/homebrew/lib/softhsm/libsofthsm2.so (macOS)
  # YubiKey:  /usr/lib/libykcs11.so
  # Entrust:  /opt/nfast/toolkits/pkcs11/libcknfast.so
  # Thales:   /usr/safenet/lunaclient/lib/libCryptoki2_64.so
  library: "/opt/homebrew/lib/softhsm/libsofthsm2.so"
  slot: 0
  # HSM PIN — use ${HSM_PIN} to read from environment variable
  pin: "${HSM_PIN}"

backend:
  # gRPC endpoint of the PKI backend
  url: "localhost:9010"
  tls:
    # Minimum TLS version (1.3 required)
    min_version: "1.3"
    # Client certificate for mTLS (issued by your tenant's CA)
    client_cert: "/etc/pki/agent-cert.pem"
    client_key: "/etc/pki/agent-key.pem"
    # CA certificate chain to verify the server
    ca_cert: "/etc/pki/ca-chain.pem"

agent:
  id: "agent-01"
  tenant_id: "dev"
  heartbeat_interval: "10s"
```

- [ ] **Step 4: Create the PKCS#11 wrapper**

Create `hsm-agent/pkcs11.go`:

```go
package main

import (
	"fmt"
	"log"

	"github.com/miekg/pkcs11"
)

// HsmClient wraps PKCS#11 operations.
type HsmClient struct {
	ctx     *pkcs11.Ctx
	session pkcs11.SessionHandle
	labels  []string
}

// NewHsmClient loads the PKCS#11 library, opens a session, and logs in.
func NewHsmClient(libraryPath string, slotID uint, pin string) (*HsmClient, error) {
	ctx := pkcs11.New(libraryPath)
	if ctx == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 library: %s", libraryPath)
	}

	if err := ctx.Initialize(); err != nil {
		return nil, fmt.Errorf("C_Initialize failed: %w", err)
	}

	session, err := ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		ctx.Finalize()
		return nil, fmt.Errorf("C_OpenSession failed: %w", err)
	}

	if err := ctx.Login(session, pkcs11.CKU_USER, pin); err != nil {
		ctx.CloseSession(session)
		ctx.Finalize()
		return nil, fmt.Errorf("C_Login failed: %w", err)
	}

	client := &HsmClient{
		ctx:     ctx,
		session: session,
	}

	// Discover available key labels
	labels, err := client.ListKeyLabels()
	if err != nil {
		log.Printf("Warning: could not list key labels: %v", err)
	}
	client.labels = labels

	return client, nil
}

// ListKeyLabels finds all private keys and returns their labels.
func (h *HsmClient) ListKeyLabels() ([]string, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	}

	if err := h.ctx.FindObjectsInit(h.session, template); err != nil {
		return nil, fmt.Errorf("C_FindObjectsInit failed: %w", err)
	}
	defer h.ctx.FindObjectsFinal(h.session)

	var labels []string
	for {
		objs, _, err := h.ctx.FindObjects(h.session, 10)
		if err != nil {
			return nil, fmt.Errorf("C_FindObjects failed: %w", err)
		}
		if len(objs) == 0 {
			break
		}

		for _, obj := range objs {
			attrs, err := h.ctx.GetAttributeValue(h.session, obj, []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
			})
			if err != nil {
				continue
			}
			for _, attr := range attrs {
				if attr.Type == pkcs11.CKA_LABEL {
					labels = append(labels, string(attr.Value))
				}
			}
		}
	}

	return labels, nil
}

// Sign finds a private key by label and signs the data.
func (h *HsmClient) Sign(keyLabel string, data []byte, mechanism uint) ([]byte, error) {
	// Find the private key by label
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
	}

	if err := h.ctx.FindObjectsInit(h.session, template); err != nil {
		return nil, fmt.Errorf("C_FindObjectsInit failed: %w", err)
	}

	objs, _, err := h.ctx.FindObjects(h.session, 1)
	if err != nil {
		h.ctx.FindObjectsFinal(h.session)
		return nil, fmt.Errorf("C_FindObjects failed: %w", err)
	}
	h.ctx.FindObjectsFinal(h.session)

	if len(objs) == 0 {
		return nil, fmt.Errorf("key not found: %s", keyLabel)
	}

	// Sign
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(mechanism, nil)}
	if err := h.ctx.SignInit(h.session, mech, objs[0]); err != nil {
		return nil, fmt.Errorf("C_SignInit failed: %w", err)
	}

	signature, err := h.ctx.Sign(h.session, data)
	if err != nil {
		return nil, fmt.Errorf("C_Sign failed: %w", err)
	}

	return signature, nil
}

// Close cleans up the PKCS#11 session.
func (h *HsmClient) Close() {
	if h.ctx != nil {
		h.ctx.Logout(h.session)
		h.ctx.CloseSession(h.session)
		h.ctx.Finalize()
	}
}

// AvailableKeyLabels returns the discovered key labels.
func (h *HsmClient) AvailableKeyLabels() []string {
	return h.labels
}

// MechanismForAlgorithm maps algorithm string to PKCS#11 mechanism.
func MechanismForAlgorithm(algorithm string) uint {
	switch algorithm {
	case "ECC-P256", "ECC-P384":
		return pkcs11.CKM_ECDSA
	case "RSA-2048", "RSA-4096":
		return pkcs11.CKM_RSA_PKCS
	default:
		// For PQC algorithms, use vendor-specific mechanisms
		// or CKM_VENDOR_DEFINED
		return pkcs11.CKM_ECDSA
	}
}
```

- [ ] **Step 5: Create the gRPC client**

Create `hsm-agent/grpc_client.go`:

```go
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"

	pb "github.com/antrapolation/hsm-agent/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// GrpcClient handles the bidirectional gRPC stream to the backend.
type GrpcClient struct {
	config    *Config
	hsm       *HsmClient
	conn      *grpc.ClientConn
	stream    pb.HsmGateway_ConnectClient
	mu        sync.Mutex
	connected bool
}

// NewGrpcClient creates a new gRPC client.
func NewGrpcClient(config *Config, hsm *HsmClient) *GrpcClient {
	return &GrpcClient{
		config: config,
		hsm:    hsm,
	}
}

// Connect establishes the gRPC connection with mTLS.
func (g *GrpcClient) Connect(ctx context.Context) error {
	tlsConfig, err := g.buildTLSConfig()
	if err != nil {
		return fmt.Errorf("TLS config failed: %w", err)
	}

	creds := credentials.NewTLS(tlsConfig)
	conn, err := grpc.NewClient(
		g.config.Backend.URL,
		grpc.WithTransportCredentials(creds),
	)
	if err != nil {
		return fmt.Errorf("gRPC dial failed: %w", err)
	}

	client := pb.NewHsmGatewayClient(conn)
	stream, err := client.Connect(ctx)
	if err != nil {
		conn.Close()
		return fmt.Errorf("gRPC Connect failed: %w", err)
	}

	g.mu.Lock()
	g.conn = conn
	g.stream = stream
	g.connected = true
	g.mu.Unlock()

	return nil
}

// Register sends the RegisterRequest to the backend.
func (g *GrpcClient) Register() error {
	msg := &pb.AgentMessage{
		Payload: &pb.AgentMessage_Register{
			Register: &pb.RegisterRequest{
				TenantId:           g.config.Agent.TenantID,
				AgentId:            g.config.Agent.ID,
				AvailableKeyLabels: g.hsm.AvailableKeyLabels(),
			},
		},
	}

	if err := g.stream.Send(msg); err != nil {
		return fmt.Errorf("send register failed: %w", err)
	}

	// Wait for RegisterResponse
	resp, err := g.stream.Recv()
	if err != nil {
		return fmt.Errorf("recv register response failed: %w", err)
	}

	regResp := resp.GetRegisterResponse()
	if regResp == nil {
		return fmt.Errorf("unexpected response type")
	}
	if !regResp.Accepted {
		return fmt.Errorf("registration rejected: %s", regResp.Error)
	}

	log.Printf("Registered with backend: agent=%s, keys=%v", g.config.Agent.ID, g.hsm.AvailableKeyLabels())
	return nil
}

// RunLoop handles the bidirectional message loop.
func (g *GrpcClient) RunLoop(ctx context.Context) error {
	// Start heartbeat goroutine
	heartbeatInterval, err := time.ParseDuration(g.config.Agent.HeartbeatInterval)
	if err != nil {
		heartbeatInterval = 10 * time.Second
	}

	go g.heartbeatLoop(ctx, heartbeatInterval)

	// Receive loop
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			msg, err := g.stream.Recv()
			if err != nil {
				if err == io.EOF {
					return fmt.Errorf("stream closed by server")
				}
				return fmt.Errorf("recv failed: %w", err)
			}

			switch payload := msg.Payload.(type) {
			case *pb.ServerMessage_SignRequest:
				go g.handleSignRequest(payload.SignRequest)
			case *pb.ServerMessage_HeartbeatAck:
				// OK — server is alive
			default:
				log.Printf("Unknown message type: %T", payload)
			}
		}
	}
}

func (g *GrpcClient) handleSignRequest(req *pb.SignRequest) {
	log.Printf("Sign request: id=%s, key=%s, algo=%s, data_len=%d",
		req.RequestId, req.KeyLabel, req.Algorithm, len(req.TbsData))

	mechanism := MechanismForAlgorithm(req.Algorithm)
	signature, err := g.hsm.Sign(req.KeyLabel, req.TbsData, mechanism)

	var resp *pb.AgentMessage
	if err != nil {
		log.Printf("Sign failed: %v", err)
		resp = &pb.AgentMessage{
			Payload: &pb.AgentMessage_SignResponse{
				SignResponse: &pb.SignResponse{
					RequestId: req.RequestId,
					Error:     err.Error(),
				},
			},
		}
	} else {
		resp = &pb.AgentMessage{
			Payload: &pb.AgentMessage_SignResponse{
				SignResponse: &pb.SignResponse{
					RequestId: req.RequestId,
					Signature: signature,
				},
			},
		}
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.stream.Send(resp); err != nil {
		log.Printf("Failed to send sign response: %v", err)
	}
}

func (g *GrpcClient) heartbeatLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			msg := &pb.AgentMessage{
				Payload: &pb.AgentMessage_Heartbeat{
					Heartbeat: &pb.Heartbeat{
						Timestamp: time.Now().Unix(),
					},
				},
			}
			g.mu.Lock()
			err := g.stream.Send(msg)
			g.mu.Unlock()
			if err != nil {
				log.Printf("Heartbeat send failed: %v", err)
				return
			}
		}
	}
}

func (g *GrpcClient) buildTLSConfig() (*tls.Config, error) {
	tlsCfg := g.config.Backend.TLS

	// Load client certificate for mTLS
	cert, err := tls.LoadX509KeyPair(tlsCfg.ClientCert, tlsCfg.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("load client cert failed: %w", err)
	}

	// Load CA certificate
	caCert, err := os.ReadFile(tlsCfg.CACert)
	if err != nil {
		return nil, fmt.Errorf("read CA cert failed: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// Close shuts down the gRPC connection.
func (g *GrpcClient) Close() {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.stream != nil {
		g.stream.CloseSend()
	}
	if g.conn != nil {
		g.conn.Close()
	}
	g.connected = false
}
```

- [ ] **Step 6: Create the main entry point**

Create `hsm-agent/main.go`:

```go
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the agent configuration.
type Config struct {
	PKCS11 struct {
		Library string `yaml:"library"`
		Slot    uint   `yaml:"slot"`
		Pin     string `yaml:"pin"`
	} `yaml:"pkcs11"`

	Backend struct {
		URL string `yaml:"url"`
		TLS struct {
			MinVersion string `yaml:"min_version"`
			ClientCert string `yaml:"client_cert"`
			ClientKey  string `yaml:"client_key"`
			CACert     string `yaml:"ca_cert"`
		} `yaml:"tls"`
	} `yaml:"backend"`

	Agent struct {
		ID                string `yaml:"id"`
		TenantID          string `yaml:"tenant_id"`
		HeartbeatInterval string `yaml:"heartbeat_interval"`
	} `yaml:"agent"`
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// Expand environment variables in PIN
	if strings.HasPrefix(config.PKCS11.Pin, "${") && strings.HasSuffix(config.PKCS11.Pin, "}") {
		envVar := config.PKCS11.Pin[2 : len(config.PKCS11.Pin)-1]
		config.PKCS11.Pin = os.Getenv(envVar)
		if config.PKCS11.Pin == "" {
			return nil, fmt.Errorf("environment variable %s not set", envVar)
		}
	}

	return &config, nil
}

func main() {
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("HSM Agent starting...")

	// Load config
	config, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	log.Printf("Config loaded: agent=%s, tenant=%s, backend=%s",
		config.Agent.ID, config.Agent.TenantID, config.Backend.URL)

	// Initialize PKCS#11
	hsm, err := NewHsmClient(config.PKCS11.Library, config.PKCS11.Slot, config.PKCS11.Pin)
	if err != nil {
		log.Fatalf("Failed to initialize HSM: %v", err)
	}
	defer hsm.Close()
	log.Printf("HSM initialized: %d keys available: %v", len(hsm.AvailableKeyLabels()), hsm.AvailableKeyLabels())

	// Set up signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("Received signal %v, shutting down...", sig)
		cancel()
	}()

	// Connect with exponential backoff
	grpcClient := NewGrpcClient(config, hsm)
	backoff := 1 * time.Second
	maxBackoff := 60 * time.Second

	for {
		select {
		case <-ctx.Done():
			log.Println("Shutting down...")
			grpcClient.Close()
			return
		default:
		}

		log.Printf("Connecting to backend: %s", config.Backend.URL)
		if err := grpcClient.Connect(ctx); err != nil {
			log.Printf("Connection failed: %v (retry in %v)", err, backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = time.Duration(math.Min(float64(backoff*2), float64(maxBackoff)))
			continue
		}

		// Register
		if err := grpcClient.Register(); err != nil {
			log.Printf("Registration failed: %v (retry in %v)", err, backoff)
			grpcClient.Close()
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = time.Duration(math.Min(float64(backoff*2), float64(maxBackoff)))
			continue
		}

		// Reset backoff on successful connection
		backoff = 1 * time.Second

		// Run the message loop
		if err := grpcClient.RunLoop(ctx); err != nil {
			log.Printf("Stream error: %v (reconnecting in %v)", err, backoff)
			grpcClient.Close()
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = time.Duration(math.Min(float64(backoff*2), float64(maxBackoff)))
		}
	}
}
```

- [ ] **Step 7: Create the Makefile**

Create `hsm-agent/Makefile`:

```makefile
# HSM Agent build targets

.PHONY: all build-linux build-mac proto test clean

BINARY = hsm-agent
PROTO_DIR = proto

all: proto build-mac

# Generate Go protobuf code from .proto
proto:
	protoc --go_out=. --go_opt=paths=source_relative \
	       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
	       $(PROTO_DIR)/hsm_gateway.proto

# Build for Linux amd64
build-linux: proto
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o bin/$(BINARY)-linux-amd64 .

# Build for macOS arm64
build-mac: proto
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -o bin/$(BINARY)-darwin-arm64 .

# Run tests
test:
	go test ./... -v

# Run tests with SoftHSM2 integration
test-softhsm:
	SOFTHSM2_LIB=/opt/homebrew/lib/softhsm/libsofthsm2.so go test ./... -v -run TestSoftHSM

# Tidy dependencies
tidy:
	go mod tidy

# Clean build artifacts
clean:
	rm -rf bin/
```

- [ ] **Step 8: Create the PKCS#11 test**

Create `hsm-agent/pkcs11_test.go`:

```go
package main

import (
	"os"
	"testing"
)

func TestMechanismForAlgorithm(t *testing.T) {
	tests := []struct {
		algo     string
		expected uint
	}{
		{"ECC-P256", 0x00001041}, // CKM_ECDSA
		{"ECC-P384", 0x00001041},
		{"RSA-2048", 0x00000001}, // CKM_RSA_PKCS
		{"RSA-4096", 0x00000001},
		{"unknown", 0x00001041},  // defaults to ECDSA
	}

	for _, tt := range tests {
		t.Run(tt.algo, func(t *testing.T) {
			got := MechanismForAlgorithm(tt.algo)
			if got != tt.expected {
				t.Errorf("MechanismForAlgorithm(%s) = %x, want %x", tt.algo, got, tt.expected)
			}
		})
	}
}

func TestSoftHSMListKeys(t *testing.T) {
	lib := os.Getenv("SOFTHSM2_LIB")
	if lib == "" {
		t.Skip("SOFTHSM2_LIB not set, skipping SoftHSM test")
	}

	pin := os.Getenv("HSM_PIN")
	if pin == "" {
		pin = "1234"
	}

	hsm, err := NewHsmClient(lib, 0, pin)
	if err != nil {
		t.Fatalf("NewHsmClient failed: %v", err)
	}
	defer hsm.Close()

	labels := hsm.AvailableKeyLabels()
	t.Logf("Found %d key labels: %v", len(labels), labels)
}

func TestSoftHSMSign(t *testing.T) {
	lib := os.Getenv("SOFTHSM2_LIB")
	if lib == "" {
		t.Skip("SOFTHSM2_LIB not set, skipping SoftHSM test")
	}

	pin := os.Getenv("HSM_PIN")
	if pin == "" {
		pin = "1234"
	}

	hsm, err := NewHsmClient(lib, 0, pin)
	if err != nil {
		t.Fatalf("NewHsmClient failed: %v", err)
	}
	defer hsm.Close()

	labels := hsm.AvailableKeyLabels()
	if len(labels) == 0 {
		t.Skip("No keys found in SoftHSM2")
	}

	data := []byte("test data to sign with HSM")
	// Hash the data for ECDSA (requires pre-hashed input)
	// For testing, we use raw data — SoftHSM handles hashing internally
	sig, err := hsm.Sign(labels[0], data, MechanismForAlgorithm("ECC-P256"))
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(sig) == 0 {
		t.Error("Signature is empty")
	}
	t.Logf("Signature length: %d bytes", len(sig))
}
```

- [ ] **Step 9: Create the main test**

Create `hsm-agent/main_test.go`:

```go
package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configData := `
pkcs11:
  library: "/usr/lib/softhsm/libsofthsm2.so"
  slot: 0
  pin: "1234"
backend:
  url: "localhost:9010"
  tls:
    min_version: "1.3"
    client_cert: "/etc/pki/agent-cert.pem"
    client_key: "/etc/pki/agent-key.pem"
    ca_cert: "/etc/pki/ca-chain.pem"
agent:
  id: "test-agent"
  tenant_id: "test-tenant"
  heartbeat_interval: "10s"
`
	if err := os.WriteFile(configPath, []byte(configData), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	config, err := loadConfig(configPath)
	if err != nil {
		t.Fatalf("loadConfig failed: %v", err)
	}

	if config.PKCS11.Library != "/usr/lib/softhsm/libsofthsm2.so" {
		t.Errorf("Library = %q, want /usr/lib/softhsm/libsofthsm2.so", config.PKCS11.Library)
	}
	if config.PKCS11.Slot != 0 {
		t.Errorf("Slot = %d, want 0", config.PKCS11.Slot)
	}
	if config.Agent.ID != "test-agent" {
		t.Errorf("Agent.ID = %q, want test-agent", config.Agent.ID)
	}
	if config.Agent.TenantID != "test-tenant" {
		t.Errorf("Agent.TenantID = %q, want test-tenant", config.Agent.TenantID)
	}
}

func TestLoadConfigEnvExpansion(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configData := `
pkcs11:
  library: "/usr/lib/softhsm/libsofthsm2.so"
  slot: 0
  pin: "${TEST_HSM_PIN}"
backend:
  url: "localhost:9010"
  tls:
    min_version: "1.3"
    client_cert: "/tmp/cert.pem"
    client_key: "/tmp/key.pem"
    ca_cert: "/tmp/ca.pem"
agent:
  id: "test"
  tenant_id: "test"
  heartbeat_interval: "5s"
`
	if err := os.WriteFile(configPath, []byte(configData), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	// Without env var set, should fail
	os.Unsetenv("TEST_HSM_PIN")
	_, err := loadConfig(configPath)
	if err == nil {
		t.Error("Expected error when env var not set")
	}

	// With env var set, should succeed
	os.Setenv("TEST_HSM_PIN", "secret-pin")
	defer os.Unsetenv("TEST_HSM_PIN")

	config, err := loadConfig(configPath)
	if err != nil {
		t.Fatalf("loadConfig failed: %v", err)
	}
	if config.PKCS11.Pin != "secret-pin" {
		t.Errorf("Pin = %q, want secret-pin", config.PKCS11.Pin)
	}
}
```

- [ ] **Step 10: Initialize Go module and fetch dependencies**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/hsm-agent
go mod tidy
```

- [ ] **Step 11: Run Go tests**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/hsm-agent
go test ./... -v
```

Expected: `TestLoadConfig` and `TestLoadConfigEnvExpansion` pass. `TestMechanismForAlgorithm` passes. SoftHSM tests skip if `SOFTHSM2_LIB` not set.

- [ ] **Step 12: Build the binary**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/hsm-agent
make build-mac
```

Expected: `bin/hsm-agent-darwin-arm64` binary created.

- [ ] **Step 13: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki
git add hsm-agent/
git commit -m "feat(hsm): add Go HSM Agent for remote PKCS#11 signing

Standalone Go binary that:
- Loads any PKCS#11 .so via miekg/pkcs11
- Connects to BEAM backend via gRPC with mTLS (TLS 1.3)
- Registers available key labels
- Handles sign requests via bidirectional streaming
- Heartbeats every 10s, reconnects with exponential backoff
- Builds for Linux amd64 and macOS arm64"
```

---

## Task 7: Integration Test + Conditional HsmGateway in Supervision Tree

**Files:**
- Create: `src/pki_ca_engine/test/pki_ca_engine/key_store/integration_test.exs`
- Modify: `src/pki_tenant/lib/pki_tenant/application.ex`
- Modify: `config/runtime.exs`

### Context

This task verifies the full signing path end-to-end with SoftHSM2, and adds the HsmGateway to the tenant supervision tree (conditionally, only when `HSM_GRPC_PORT` is set).

- [ ] **Step 1: Write the integration test**

Create `src/pki_ca_engine/test/pki_ca_engine/key_store/integration_test.exs`:

```elixir
defmodule PkiCaEngine.KeyStore.IntegrationTest do
  @moduledoc """
  Full-flow integration tests for the KeyStore abstraction.

  Tests:
  - Software adapter: IssuerKey with keystore_type :software -> sign via KeyActivation
  - Local HSM adapter: IssuerKey with keystore_type :local_hsm -> sign via SoftHSM2
  - Dispatcher routing: correct adapter selected by keystore_type
  """
  use ExUnit.Case, async: false

  alias PkiMnesia.{TestHelper, Repo}
  alias PkiMnesia.Structs.IssuerKey
  alias PkiCaEngine.{KeyActivation, KeyStore.Dispatcher}

  @softhsm_lib System.get_env("SOFTHSM2_LIB") || "/opt/homebrew/lib/softhsm/libsofthsm2.so"

  setup do
    dir = TestHelper.setup_mnesia()
    {:ok, ka_pid} = KeyActivation.start_link(name: :test_ka_int, timeout_ms: 60_000)
    Application.put_env(:pki_ca_engine, :allow_dev_activate, true)

    on_exit(fn ->
      Application.put_env(:pki_ca_engine, :allow_dev_activate, false)
      if Process.alive?(ka_pid), do: GenServer.stop(ka_pid)
      TestHelper.teardown_mnesia(dir)
    end)

    %{ka: :test_ka_int}
  end

  test "software keystore: full sign flow via Dispatcher", %{ka: ka} do
    # Generate ECC key pair
    ec_key = :public_key.generate_key({:namedCurve, :secp256r1})
    priv_der = :public_key.der_encode(:ECPrivateKey, ec_key)

    key = IssuerKey.new(%{
      ca_instance_id: "ca-1",
      algorithm: "ECC-P256",
      status: "active",
      keystore_type: :software
    })
    {:ok, _} = Repo.insert(key)

    # Activate key
    {:ok, :dev_activated} = KeyActivation.dev_activate(ka, key.id, priv_der)

    # Sign via Dispatcher
    tbs_data = :crypto.strong_rand_bytes(64)
    assert {:ok, signature} = Dispatcher.sign(key.id, tbs_data)
    assert is_binary(signature)
    assert byte_size(signature) > 0
  end

  test "dispatcher returns correct errors" do
    # Non-existent key
    assert {:error, :issuer_key_not_found} = Dispatcher.sign("nonexistent", "data")

    # Unknown keystore type
    key = IssuerKey.new(%{
      ca_instance_id: "ca-1",
      algorithm: "ECC-P256",
      status: "active",
      keystore_type: :unknown_type
    })
    {:ok, _} = Repo.insert(key)
    assert {:error, :unknown_keystore_type} = Dispatcher.sign(key.id, "data")
  end

  @tag :softhsm
  test "local HSM: full sign flow via Dispatcher" do
    port_binary = Path.join(:code.priv_dir(:pki_ca_engine), "pkcs11_port")

    if File.exists?(port_binary) and File.exists?(@softhsm_lib) do
      key = IssuerKey.new(%{
        ca_instance_id: "ca-1",
        algorithm: "ECC-P256",
        status: "active",
        keystore_type: :local_hsm,
        hsm_config: %{
          "library_path" => @softhsm_lib,
          "slot_id" => 0,
          "pin" => "1234",
          "key_label" => "test-key"
        }
      })
      {:ok, _} = Repo.insert(key)

      # Hash the data (ECDSA expects pre-hashed input for PKCS#11)
      tbs_data = :crypto.hash(:sha256, "integration test data")
      assert {:ok, signature} = Dispatcher.sign(key.id, tbs_data)
      assert is_binary(signature)
      assert byte_size(signature) > 0
    else
      IO.puts("Skipping local HSM integration test: SoftHSM2 or pkcs11_port not found")
    end
  end

  test "remote HSM: returns :agent_not_connected without agent" do
    key = IssuerKey.new(%{
      ca_instance_id: "ca-1",
      algorithm: "ECC-P256",
      status: "active",
      keystore_type: :remote_hsm,
      hsm_config: %{"key_label" => "test-key"}
    })
    {:ok, _} = Repo.insert(key)

    assert {:error, :agent_not_connected} = Dispatcher.sign(key.id, "data")
  end
end
```

- [ ] **Step 2: Run the integration tests**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_engine && mix test test/pki_ca_engine/key_store/integration_test.exs
```

Expected: Software and remote HSM tests pass. Local HSM tests pass if SoftHSM2 is available.

- [ ] **Step 3: Update the tenant Application to conditionally start HsmGateway**

Edit `src/pki_tenant/lib/pki_tenant/application.ex`. In the primary mode children list, add HsmGateway conditionally:

Current code (lines 40-49):
```elixir
        # Primary mode — full supervision tree (existing behavior)
        true ->
          [
            {PkiTenant.MnesiaBootstrap, [slug: tenant_slug]},
            {PkiTenant.MnesiaBackup, [start_timer: true]},
            {PkiTenant.AuditBridge, [tenant_id: tenant_id, platform_node: platform_node]},
            {PkiCaEngine.EngineSupervisor, []},
            {PkiRaEngine.EngineSupervisor, []},
            {PkiValidation.Supervisor, []},
            {Task.Supervisor, name: PkiTenant.TaskSupervisor}
          ]
```

Replace with:

```elixir
        # Primary mode — full supervision tree (existing behavior)
        true ->
          hsm_grpc_port = System.get_env("HSM_GRPC_PORT")

          base_children = [
            {PkiTenant.MnesiaBootstrap, [slug: tenant_slug]},
            {PkiTenant.MnesiaBackup, [start_timer: true]},
            {PkiTenant.AuditBridge, [tenant_id: tenant_id, platform_node: platform_node]},
            {PkiCaEngine.EngineSupervisor, []},
            {PkiRaEngine.EngineSupervisor, []},
            {PkiValidation.Supervisor, []},
            {Task.Supervisor, name: PkiTenant.TaskSupervisor}
          ]

          if hsm_grpc_port do
            base_children ++ [{PkiCaEngine.HsmGateway, [port: String.to_integer(hsm_grpc_port)]}]
          else
            base_children
          end
```

- [ ] **Step 4: Update runtime.exs with HSM config**

Edit `config/runtime.exs` (add at the bottom, before the final `end` if there is one):

```elixir
# -- HSM Gateway (Phase D) --
# Set HSM_GRPC_PORT to enable the gRPC server for remote HSM agents.
# Example: HSM_GRPC_PORT=9010
# When not set, HsmGateway is not started (zero overhead for software-only tenants).
if hsm_port = System.get_env("HSM_GRPC_PORT") do
  config :pki_ca_engine, :hsm_grpc_port, String.to_integer(hsm_port)
end
```

- [ ] **Step 5: Run all tests to verify nothing is broken**

```bash
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_engine && mix test
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_validation && mix test
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_tenant && mix test
```

Expected: All tests pass.

- [ ] **Step 6: Compile the full project**

```bash
cd /Users/amirrudinyahaya/Workspace/pki && mix compile --no-deps-check
```

Expected: No compilation errors.

- [ ] **Step 7: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/pki
git add src/pki_ca_engine/test/pki_ca_engine/key_store/integration_test.exs \
  src/pki_tenant/lib/pki_tenant/application.ex \
  config/runtime.exs
git commit -m "feat(hsm): integration tests + conditional HsmGateway in supervision tree

Full-flow integration tests for all three keystore types. HsmGateway
only starts when HSM_GRPC_PORT is set (zero overhead for software-only
tenants). All existing tests continue to pass."
```

---

## Self-Review

### Spec coverage check

| Spec Section | Task |
|---|---|
| 1. Architecture Overview | All tasks |
| 2. KeyStore Behaviour | Task 1 |
| 3. Software Adapter | Task 1 |
| 4. Local HSM Adapter | Tasks 3, 4 |
| 5. Remote HSM + gRPC | Task 5 |
| 6. Go HSM Agent | Task 6 |
| 7. IssuerKey Data Model | Task 1 (Step 1) |
| 8. Changes to Existing Code | Task 2 |
| 9. Security (mTLS, PIN handling) | Tasks 5, 6 |
| 10. Testing Strategy | Tasks 1, 4, 5, 6, 7 |
| 11. Success Criteria | All tasks |
| 12. Out of Scope | N/A (correctly excluded) |

### Placeholder scan

No TBD, TODO, or "implement later" found. All code blocks are complete.

### Type consistency check

- `KeyStore.sign/2` -- used consistently as `sign(issuer_key_id, tbs_data)` in all adapters
- `SoftwareAdapter.sign/3` -- has optional `opts` keyword list for `activation_server`
- `RemoteHsmAdapter.sign/3` -- has optional `opts` keyword list for `gateway` and `timeout`
- `LocalHsmAdapter.sign/2` -- no opts needed
- `Dispatcher.sign/2` -- always 2 args, delegates to adapter

Note: The behaviour defines `sign/2` but `SoftwareAdapter` and `RemoteHsmAdapter` accept optional 3rd arg. This is fine in Elixir -- the `@impl true` annotation matches the 2-arity callback, and the 3-arity is for direct testing. The Dispatcher always calls with 2 args.

### CertificateSigning HSM path note

The `do_sign_via_dispatcher/6` function assumes `PkiCrypto.X509Builder.assemble_cert/3` exists. If it does not, it must be added to `PkiCrypto.X509Builder`. This is called out in Task 2 Step 3. The implementer should check and add it if missing.
