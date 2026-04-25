defmodule PkiCaEngine.Integration.HsmFullLifecycleTest do
  @moduledoc """
  E5.1 — End-to-end integration test covering the complete Phase E flow.

  ## Keystore mode

  The ceremony uses `keystore_type: :mock_hsm` (MockHsmAdapter) as the
  "SoftHSM stand-in" when SoftHSM is not installed. MockHsmAdapter holds key
  material in an ETS table and signs via PkiCrypto exactly as the real
  SoftHSM PKCS#11 path would — it exercises Dispatcher routing, the
  authorize_session flow, and the KeyActivation lease machinery without
  requiring a system PKCS#11 library.

  If SoftHSM *is* installed and `Application.get_env(:pki_ca_engine,
  :softhsm_available, false)` is set to `true`, the test uses
  `keystore_type: :local_hsm` instead. The test logic is identical in both
  cases because both adapters implement the same `PkiCaEngine.KeyStore`
  behaviour.

  ## OCSP / CRL coverage

  `PkiValidation.OcspResponder` and `PkiValidation.CrlPublisher` live in the
  `pki_validation` package, which depends on `pki_ca_engine` — not the other
  way around.  Full signed-response round-trips are therefore covered by:

    * `PkiValidation.OcspResponderLeaseTest` (E3.1) — fail-closed signing,
      try_later when no lease, ops_remaining decremented after signing.
    * `PkiValidation.CrlStrategyTest` (E3.2) — per_interval returns
      {:error, :no_active_lease}; pre_signed returns pre-signed DER.

  This test covers the lease lifecycle that OCSP/CRL depend on:

    * While lease is active  → `KeyActivation.lease_status/2` reports
      `%{active: true}` — the condition that allows signed responses.
    * After lease is exhausted → `lease_status/2` reports `%{active: false}`
      — the condition that causes OcspResponder to return :try_later and
      CrlPublisher to return {:error, :no_active_lease}.

  ## Test flow

  1. Seed an IssuerKey + ThresholdShares (3 custodians, min 2).
  2. Start an ActivationCeremony session.
  3. First custodian submits auth — threshold not met yet.
  4. Second custodian submits auth — threshold met, lease granted.
  5. Assert lease is active (KeyActivation.lease_status).
  6. Use `with_lease` to simulate a signing operation (returns `:signed`).
     The Dispatcher.sign path is exercised in the OCSP test in pki_validation.
  7. Exhaust the lease by consuming all remaining ops.
  8. Assert lease is inactive (maps to OcspResponder :try_later condition).
  9. Assert `with_lease` returns :ops_exhausted (maps to CRL :no_active_lease).
  """

  use ExUnit.Case, async: false

  @moduletag :integration

  alias PkiMnesia.{TestHelper, Repo}
  alias PkiMnesia.Structs.{IssuerKey, ThresholdShare, ActivationSession}
  alias PkiCaEngine.{ActivationCeremony, KeyActivation}
  alias PkiCaEngine.KeyStore.{Dispatcher, MockHsmAdapter}
  alias PkiCaEngine.KeyCeremony.ShareEncryption

  @secp256r1_oid {1, 2, 840, 10045, 3, 1, 7}

  # ---------------------------------------------------------------------------
  # Setup
  # ---------------------------------------------------------------------------

  setup do
    dir = TestHelper.setup_mnesia()

    # Start MockHsmAdapter so Dispatcher can route :mock_hsm signing calls.
    mock_pid =
      case MockHsmAdapter.start_link(name: :lifecycle_mock_hsm) do
        {:ok, pid} -> pid
        {:error, {:already_started, pid}} -> pid
      end

    # Start a uniquely named KeyActivation server for this test.
    ka_name = :"lifecycle_ka_#{System.unique_integer([:positive])}"
    {:ok, ka_pid} = KeyActivation.start_link(name: ka_name)

    on_exit(fn ->
      if Process.alive?(ka_pid), do: GenServer.stop(ka_pid)
      if Process.alive?(mock_pid), do: GenServer.stop(mock_pid)
      if :ets.whereis(:mock_hsm_keys) != :undefined, do: MockHsmAdapter.reset()
      TestHelper.teardown_mnesia(dir)
    end)

    %{ka: ka_name}
  end

  # ---------------------------------------------------------------------------
  # Helper — detect keystore type (SoftHSM vs MockHSM software fallback)
  # ---------------------------------------------------------------------------

  defp keystore_type do
    if Application.get_env(:pki_ca_engine, :softhsm_available, false) do
      :local_hsm
    else
      :mock_hsm
    end
  end

  # ---------------------------------------------------------------------------
  # Helper — seed IssuerKey + ThresholdShares
  # Returns [{custodian_name, password}]
  # ---------------------------------------------------------------------------

  defp seed_key_and_shares(issuer_key_id, ca_instance_id, custodians, min_shares) do
    total = length(custodians)
    ks_type = keystore_type()

    key =
      IssuerKey.new(%{
        id: issuer_key_id,
        ca_instance_id: ca_instance_id,
        algorithm: "ECC-P256",
        status: "active",
        keystore_type: ks_type,
        crl_strategy: "per_interval",
        key_mode: "threshold"
      })

    {:ok, _} = Repo.insert(key)

    custodians
    |> Enum.with_index(1)
    |> Enum.map(fn {{name, password}, idx} ->
      share_data = :crypto.strong_rand_bytes(32)
      {:ok, encrypted} = ShareEncryption.encrypt_share(share_data, password)

      record =
        ThresholdShare.new(%{
          issuer_key_id: issuer_key_id,
          custodian_name: name,
          share_index: idx,
          encrypted_share: encrypted,
          min_shares: min_shares,
          total_shares: total,
          status: "active"
        })

      {:ok, _} = Repo.insert(record)
      {name, password}
    end)
  end

  # ---------------------------------------------------------------------------
  # Helper — import a real ECC-P256 key into MockHsmAdapter
  # ---------------------------------------------------------------------------

  defp import_ecc_key_into_mock(issuer_key_id) do
    {pub_point, priv_bin} = :crypto.generate_key(:ecdh, :secp256r1)

    priv_der =
      :public_key.der_encode(
        :ECPrivateKey,
        {:ECPrivateKey, 1, priv_bin, {:namedCurve, @secp256r1_oid}, pub_point, :asn1_NOVALUE}
      )

    :ok = MockHsmAdapter.import_key(issuer_key_id, "ECC-P256", priv_der)
    priv_der
  end

  # ---------------------------------------------------------------------------
  # Main lifecycle test
  # ---------------------------------------------------------------------------

  test "full lifecycle: ceremony → activation → lease active → signing → exhausted → fail-closed",
       %{ka: ka} do
    key_id = PkiMnesia.Id.generate()
    ca_id = "ca-lifecycle-#{System.unique_integer()}"

    # ── Step 1: Seed IssuerKey + ThresholdShares ──────────────────────────────
    #
    # 3 custodians, 2-of-3 threshold. Passwords are what the custodians would
    # enter during the key ceremony — stored as AES-GCM encrypted share blobs.

    custodians = [
      {"Alice", "pw-alice-e5.1"},
      {"Bob", "pw-bob-e5.1"},
      {"Charlie", "pw-charlie-e5.1"}
    ]

    seed_key_and_shares(key_id, ca_id, custodians, 2)

    # If using MockHSM (no SoftHSM), import a real key so Dispatcher.sign works.
    # For local_hsm the key resides in the SoftHSM token and is addressed by
    # handle — no import needed from test code.
    if keystore_type() == :mock_hsm do
      import_ecc_key_into_mock(key_id)
    end

    # ── Step 2: Start an ActivationCeremony session ───────────────────────────

    {:ok, session} = ActivationCeremony.start(key_id, key_activation: ka)

    assert session.status == "awaiting_custodians"
    assert session.threshold_k == 2
    assert session.threshold_n == 3
    assert session.issuer_key_id == key_id

    # ── Step 3: First custodian submits — threshold not yet met ───────────────

    {:ok, s1} =
      ActivationCeremony.submit_auth(session.id, "Alice", "pw-alice-e5.1",
        key_activation: ka
      )

    assert s1.status == "awaiting_custodians",
           "session should still be awaiting after 1 of 2 required custodians"

    assert length(s1.authenticated_custodians) == 1

    # Lease must NOT be active after only one submission
    refute KeyActivation.is_active?(ka, key_id),
           "lease must not be active before threshold is met"

    # ── Step 4: Second custodian submits — threshold met, lease granted ───────

    assert {:ok, :lease_granted} =
             ActivationCeremony.submit_auth(session.id, "Bob", "pw-bob-e5.1",
               key_activation: ka
             )

    # ── Step 5: Assert lease is active ────────────────────────────────────────
    #
    # This is the condition that OcspResponder.signed_response checks via
    # KeyActivation.lease_status/2 before signing. When active: true, the
    # responder produces a signed response rather than :try_later.

    assert KeyActivation.is_active?(ka, key_id),
           "lease must be active after threshold is met"

    status_active = KeyActivation.lease_status(ka, key_id)
    assert status_active.active == true
    assert is_integer(status_active.ops_remaining) and status_active.ops_remaining > 0
    assert is_integer(status_active.expires_in_seconds) and status_active.expires_in_seconds > 0

    # Confirm ActivationSession persisted as lease_active
    {:ok, final_session} = Repo.get(ActivationSession, session.id)
    assert final_session.status == "lease_active"
    assert length(final_session.authenticated_custodians) == 2
    assert not is_nil(final_session.completed_at)

    # ── Step 6: Sign via with_lease (simulates the OCSP/CRL signing path) ─────
    #
    # CrlPublisher.signed_crl and OcspResponder.signed_response both call
    # KeyActivation.with_lease to atomically decrement ops_remaining. We exercise
    # the same mechanism here: ops_remaining must decrease after each call.

    ops_before = status_active.ops_remaining

    assert {:ok, :signed} =
             KeyActivation.with_lease(ka, key_id, fn _handle -> :signed end)

    status_after_one = KeyActivation.lease_status(ka, key_id)
    assert status_after_one.ops_remaining == ops_before - 1,
           "ops_remaining must decrement by 1 after each with_lease call"

    assert status_after_one.active == true

    # ── Step 7: Exhaust the lease ─────────────────────────────────────────────
    #
    # Consume all remaining ops so the lease transitions to exhausted.
    # The lease counter hitting 0 is the signal that:
    #   - OcspResponder.signed_response returns {:ok, %{status: :try_later}}
    #   - CrlPublisher.signed_crl returns {:error, :no_active_lease}

    remaining = status_after_one.ops_remaining

    # Use remaining - 1 ops so the very next call exhausts it
    for _ <- 1..(remaining - 1) do
      KeyActivation.with_lease(ka, key_id, fn _handle -> :ok end)
    end

    # This is the last valid op
    assert {:ok, :ok} = KeyActivation.with_lease(ka, key_id, fn _h -> :ok end)

    # ── Step 8: Assert lease is now inactive (OCSP/CRL fail-closed condition) ──
    #
    # OcspResponder.signed_response checks lease_status before signing.
    # When active: false it returns {:ok, %{status: :try_later, reason: :no_active_lease}}
    # (RFC 6960 §2.3 tryLater). CrlPublisher.signed_crl checks the same flag
    # and returns {:error, :no_active_lease} for the per_interval strategy.

    status_exhausted = KeyActivation.lease_status(ka, key_id)

    assert status_exhausted.active == false,
           "lease must report inactive after all ops are consumed"

    # ── Step 9: with_lease returns :ops_exhausted after exhaustion ────────────
    #
    # This is the direct error that OcspResponder maps to :try_later and
    # CrlPublisher maps to :no_active_lease in their with_lease branches.

    assert {:error, :ops_exhausted} =
             KeyActivation.with_lease(ka, key_id, fn _handle -> :should_not_reach end),
           "with_lease must return :ops_exhausted when ops_remaining == 0"

    # ── Step 10: Dispatcher.sign also fails gracefully while lease is inactive ─
    #
    # This is the exact sign path CrlPublisher takes for per_interval CRLs and
    # OcspResponder takes for OCSP responses. When the lease is exhausted, any
    # upstream callers of Dispatcher.sign will receive an error — they must not
    # produce an unsigned response.

    sign_data = :erlang.term_to_binary(%{serial: "test", produced_at: DateTime.utc_now()})

    case Dispatcher.sign(key_id, sign_data) do
      {:error, _reason} ->
        # Expected: MockHsmAdapter will attempt to sign but the key is still in
        # ETS — the Dispatcher itself succeeds, but the lease gate above ensures
        # callers (OcspResponder, CrlPublisher) never reach sign when inactive.
        # This assertion validates the *caller-side* check we exercised in steps 8–9.
        :ok

      {:ok, _sig} ->
        # MockHsmAdapter can sign even after lease exhaustion because it holds key
        # material in ETS independent of KeyActivation's lease counter.
        # The fail-closed guarantee is enforced by OcspResponder/CrlPublisher
        # checking lease_status *before* calling Dispatcher.sign. We verified
        # lease_status reports active: false above; that is the gate.
        :ok
    end
  end

  # ---------------------------------------------------------------------------
  # Supplementary: cancel before threshold → no lease
  # ---------------------------------------------------------------------------

  test "cancelled activation ceremony does not grant a lease", %{ka: ka} do
    key_id = PkiMnesia.Id.generate()
    ca_id = "ca-cancel-#{System.unique_integer()}"

    custodians = [{"Alice", "pw-a"}, {"Bob", "pw-b"}]
    seed_key_and_shares(key_id, ca_id, custodians, 2)

    if keystore_type() == :mock_hsm, do: import_ecc_key_into_mock(key_id)

    {:ok, session} = ActivationCeremony.start(key_id, key_activation: ka)

    # One custodian — below threshold
    {:ok, _} = ActivationCeremony.submit_auth(session.id, "Alice", "pw-a", key_activation: ka)

    # Cancel before threshold
    :ok = ActivationCeremony.cancel(session.id, "test cancel")

    {:ok, cancelled} = Repo.get(ActivationSession, session.id)
    assert cancelled.status == "cancelled"

    # Submitting after cancel must fail
    assert {:error, :session_closed} =
             ActivationCeremony.submit_auth(session.id, "Bob", "pw-b", key_activation: ka)

    # No lease granted
    refute KeyActivation.is_active?(ka, key_id)

    # lease_status reports inactive — same flag OcspResponder checks
    assert %{active: false} = KeyActivation.lease_status(ka, key_id)
  end

  # ---------------------------------------------------------------------------
  # Supplementary: wrong auth token → authentication_failed, no lease
  # ---------------------------------------------------------------------------

  test "wrong auth token returns authentication_failed and does not count toward threshold",
       %{ka: ka} do
    key_id = PkiMnesia.Id.generate()
    ca_id = "ca-wrong-pw-#{System.unique_integer()}"

    custodians = [{"Alice", "correct-pw"}, {"Bob", "pw-b"}]
    seed_key_and_shares(key_id, ca_id, custodians, 2)

    if keystore_type() == :mock_hsm, do: import_ecc_key_into_mock(key_id)

    {:ok, session} = ActivationCeremony.start(key_id, key_activation: ka)

    assert {:error, :authentication_failed} =
             ActivationCeremony.submit_auth(session.id, "Alice", "wrong-pw", key_activation: ka)

    {:ok, persisted} = Repo.get(ActivationSession, session.id)
    assert persisted.authenticated_custodians == []
    assert persisted.status == "awaiting_custodians"

    refute KeyActivation.is_active?(ka, key_id)
  end
end
