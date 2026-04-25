defmodule PkiValidation.OcspResponderLeaseTest do
  @moduledoc """
  E3.1 — OcspResponder fail-closed behaviour: verify that signed_response/3
  returns `:try_later` when no active lease exists and a signed response when
  an active lease is present.
  """
  use ExUnit.Case, async: false

  alias PkiMnesia.{TestHelper, Repo}
  alias PkiMnesia.Structs.{CertificateStatus, IssuerKey}
  alias PkiCaEngine.KeyActivation
  alias PkiCaEngine.KeyStore.MockHsmAdapter
  alias PkiValidation.OcspResponder

  # ── Unique GenServer names per test ──────────────────────────────────────

  @ka_no_lease :test_ka_e31_no_lease
  @ka_with_lease :test_ka_e31_with_lease

  # Secp256r1 OID
  @secp256r1_oid {1, 2, 840, 10045, 3, 1, 7}

  # ── Shared setup / teardown ───────────────────────────────────────────────

  setup do
    dir = TestHelper.setup_mnesia()

    on_exit(fn ->
      # Only reset the MockHsmAdapter ETS table if it has been created
      if :ets.whereis(:mock_hsm_keys) != :undefined do
        MockHsmAdapter.reset()
      end

      TestHelper.teardown_mnesia(dir)
    end)

    :ok
  end

  # ── Test 1: No active lease → :try_later ─────────────────────────────────

  test "signed_response returns :try_later when no active lease exists" do
    {:ok, ka} = KeyActivation.start_link(name: @ka_no_lease)

    on_exit(fn ->
      if Process.alive?(ka), do: GenServer.stop(ka)
    end)

    key_id = "ocsp-no-lease-#{System.unique_integer()}"

    # Insert a certificate status so the lookup would succeed if signing were reached
    cs =
      CertificateStatus.new(%{
        serial_number: "no-lease-serial",
        issuer_key_id: key_id,
        status: "active",
        not_after:
          DateTime.utc_now() |> DateTime.add(86_400, :second) |> DateTime.truncate(:second)
      })

    {:ok, _} = Repo.insert(cs)

    # No key has been activated — lease_status returns %{active: false}
    {:ok, response} =
      OcspResponder.signed_response("no-lease-serial", key_id,
        activation_server: @ka_no_lease
      )

    assert response.status == :try_later
    assert response.reason == :no_active_lease
  end

  # ── Test 2: Active lease → signed response, ops decremented ──────────────

  test "signed_response returns signed response and decrements ops when lease is active" do
    # Start MockHsmAdapter for this test
    mock_pid =
      case MockHsmAdapter.start_link(name: :test_mock_hsm_e31) do
        {:ok, pid} -> pid
        {:error, {:already_started, pid}} -> pid
      end

    {:ok, ka} = KeyActivation.start_link(name: @ka_with_lease)

    on_exit(fn ->
      if Process.alive?(ka), do: GenServer.stop(ka)
      if Process.alive?(mock_pid), do: GenServer.stop(mock_pid)
    end)

    key_id = "ocsp-with-lease-#{System.unique_integer()}"

    # Generate a real ECC-P256 private key as DER using the same struct shape
    # as PkiCrypto.Signing.ECCP256 — 6-element tuple with pub_point as 5th element.
    {pub_point, priv_bin} = :crypto.generate_key(:ecdh, :secp256r1)

    priv_der =
      :public_key.der_encode(
        :ECPrivateKey,
        {:ECPrivateKey, 1, priv_bin, {:namedCurve, @secp256r1_oid}, pub_point, :asn1_NOVALUE}
      )

    # Import the DER-encoded key into MockHsmAdapter under our key_id
    :ok = MockHsmAdapter.import_key(key_id, "ECC-P256", priv_der)

    # Insert IssuerKey into Mnesia so Dispatcher routes to MockHsmAdapter
    issuer_key =
      IssuerKey.new(%{
        id: key_id,
        ca_instance_id: "test-ca",
        algorithm: "ECC-P256",
        status: "active",
        keystore_type: :mock_hsm
      })

    {:ok, _} = Repo.insert(issuer_key)

    # Insert a certificate status record
    cs =
      CertificateStatus.new(%{
        serial_number: "with-lease-serial",
        issuer_key_id: key_id,
        status: "active",
        not_after:
          DateTime.utc_now() |> DateTime.add(86_400, :second) |> DateTime.truncate(:second)
      })

    {:ok, _} = Repo.insert(cs)

    # Activate a lease — handle is opaque; MockHsmAdapter uses its own ETS lookup
    handle = :crypto.strong_rand_bytes(32)
    {:ok, ^key_id} = KeyActivation.activate(ka, key_id, handle, ["alice"], max_ops: 10)

    # Pre-condition: lease is active with 10 ops
    assert %{active: true, ops_remaining: 10} =
             KeyActivation.lease_status(@ka_with_lease, key_id)

    {:ok, response} =
      OcspResponder.signed_response("with-lease-serial", key_id,
        activation_server: @ka_with_lease
      )

    # Must not be a try_later
    refute response[:status] == :try_later

    # Must have a real status map, binary signature, and algorithm
    assert response.status.status == "good"
    assert is_binary(response.signature)
    assert response.algorithm == "ECC-P256"

    # ops_remaining must have decremented by 1
    assert %{active: true, ops_remaining: 9} =
             KeyActivation.lease_status(@ka_with_lease, key_id)
  end
end
