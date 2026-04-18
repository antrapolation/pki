#!/usr/bin/env elixir
# test-hsm-flow.exs — End-to-end HSM signing smoke test using SoftHSM2.
#
# Run AFTER setup-softhsm-test.sh has initialised the token:
#
#   SOFTHSM2_CONF=/tmp/pki-softhsm-tokens/softhsm2.conf \
#   SOFTHSM_LIB=/opt/homebrew/lib/softhsm/libsofthsm2.so \
#   SOFTHSM_SLOT=0 \
#   mix run scripts/test-hsm-flow.exs
#
# The script creates a transient Mnesia table, inserts a :local_hsm IssuerKey,
# and attempts to sign test data via KeyStore.Dispatcher → LocalHsmAdapter →
# Pkcs11Port → SoftHSM2 token.

alias PkiMnesia.{Repo, Structs.IssuerKey}
alias PkiCaEngine.KeyStore.Dispatcher

# ---------------------------------------------------------------------------
# Config from env
# ---------------------------------------------------------------------------
lib_path  = System.get_env("SOFTHSM_LIB")  || raise "Set SOFTHSM_LIB to the path of libsofthsm2.so"
slot_id   = String.to_integer(System.get_env("SOFTHSM_SLOT") || "0")
user_pin  = System.get_env("SOFTHSM_PIN")  || "1234"

IO.puts """

======================================================
 PKI HSM Flow Test — SoftHSM2
======================================================
  library_path : #{lib_path}
  slot_id      : #{slot_id}
  pin          : #{String.duplicate("*", String.length(user_pin))}
"""

unless File.exists?(lib_path) do
  IO.puts "ERROR: libsofthsm2.so not found at #{lib_path}"
  IO.puts "Run scripts/setup-softhsm-test.sh first and set SOFTHSM_LIB"
  System.halt(1)
end

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
defmodule HSMFlowHelper do
  def step(label, fun) do
    IO.write("  [ ] #{label}...")

    case fun.() do
      {:ok, val} ->
        IO.puts("\r  [OK] #{label}")
        {:ok, val}

      {:error, reason} ->
        IO.puts("\r  [FAIL] #{label}: #{inspect(reason)}")
        {:error, reason}

      other ->
        IO.puts("\r  [?] #{label}: #{inspect(other)}")
        {:error, other}
    end
  end

  def assert_ok!(label, fun) do
    case step(label, fun) do
      {:ok, val} -> val
      {:error, reason} ->
        IO.puts("\nFATAL: #{label} failed — #{inspect(reason)}")
        IO.puts("Ensure setup-softhsm-test.sh was run and SOFTHSM2_CONF is exported.")
        System.halt(1)
    end
  end
end

import HSMFlowHelper

# ---------------------------------------------------------------------------
# 1. RSA-2048 key via LocalHsmAdapter
# ---------------------------------------------------------------------------
IO.puts("\n--- Test 1: RSA-2048 signing via LocalHsmAdapter ---")

# Insert a temporary IssuerKey record pointing at the SoftHSM2 RSA key.
rsa_key =
  IssuerKey.new(%{
    ca_instance_id: "hsm-flow-test-ca",
    algorithm: "RSA-2048",
    status: "active",
    keystore_type: :local_hsm,
    hsm_config: %{
      "library_path" => lib_path,
      "slot_id"      => slot_id,
      "pin"          => user_pin,
      "key_label"    => "test-signing-key"
    }
  })

assert_ok!("Insert RSA IssuerKey", fn -> Repo.insert(rsa_key) end)

tbs_data = :crypto.strong_rand_bytes(64)
rsa_sig  = assert_ok!("Sign 64-byte payload (RSA-2048)", fn -> Dispatcher.sign(rsa_key.id, tbs_data) end)

IO.puts("  Signature size: #{byte_size(rsa_sig)} bytes")

# ---------------------------------------------------------------------------
# 2. ECDSA P-256 key via LocalHsmAdapter
# ---------------------------------------------------------------------------
IO.puts("\n--- Test 2: ECDSA P-256 signing via LocalHsmAdapter ---")

ecdsa_key =
  IssuerKey.new(%{
    ca_instance_id: "hsm-flow-test-ca",
    algorithm: "ECC-P256",
    status: "active",
    keystore_type: :local_hsm,
    hsm_config: %{
      "library_path" => lib_path,
      "slot_id"      => slot_id,
      "pin"          => user_pin,
      "key_label"    => "test-ecdsa-key"
    }
  })

assert_ok!("Insert ECDSA IssuerKey", fn -> Repo.insert(ecdsa_key) end)

tbs_ecdsa  = :crypto.strong_rand_bytes(32)
ecdsa_sig  = assert_ok!("Sign 32-byte payload (ECDSA P-256)", fn -> Dispatcher.sign(ecdsa_key.id, tbs_ecdsa) end)

IO.puts("  Signature size: #{byte_size(ecdsa_sig)} bytes")

# ---------------------------------------------------------------------------
# 3. key_available? check
# ---------------------------------------------------------------------------
IO.puts("\n--- Test 3: key_available? ---")

step("key_available? for RSA key", fn ->
  case Dispatcher.key_available?(rsa_key.id) do
    true  -> {:ok, true}
    false -> {:error, :returned_false}
  end
end)

step("key_available? for ECDSA key", fn ->
  case Dispatcher.key_available?(ecdsa_key.id) do
    true  -> {:ok, true}
    false -> {:error, :returned_false}
  end
end)

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
IO.puts("""

======================================================
 All HSM flow tests PASSED
======================================================
""")
