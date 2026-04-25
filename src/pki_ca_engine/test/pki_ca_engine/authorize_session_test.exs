defmodule PkiCaEngine.AuthorizeSessionTest do
  @moduledoc """
  E2.4 tests for `authorize_session`:
  1. SoftHSM-style (LocalHsmAdapter): same tokens → same deterministic handle.
  2. ActivationCeremony full flow via Dispatcher.authorize_session path.
  """
  use ExUnit.Case, async: false

  alias PkiMnesia.{TestHelper, Repo}
  alias PkiMnesia.Structs.{IssuerKey, ThresholdShare}
  alias PkiCaEngine.{ActivationCeremony, KeyActivation}
  alias PkiCaEngine.KeyStore.{Dispatcher, LocalHsmAdapter, SoftwareAdapter}
  alias PkiCaEngine.KeyCeremony.ShareEncryption

  # ---------------------------------------------------------------------------
  # Setup
  # ---------------------------------------------------------------------------

  setup do
    dir = TestHelper.setup_mnesia()

    ka_name = :"test_ka_auth_#{System.unique_integer([:positive])}"
    {:ok, ka_pid} = KeyActivation.start_link(name: ka_name)

    on_exit(fn ->
      if Process.alive?(ka_pid), do: GenServer.stop(ka_pid)
      TestHelper.teardown_mnesia(dir)
    end)

    %{ka: ka_name}
  end

  # ---------------------------------------------------------------------------
  # Helper — seed ThresholdShares + IssuerKey
  # ---------------------------------------------------------------------------

  defp seed_software_key(issuer_key_id, custodians, min_shares) do
    key =
      IssuerKey.new(%{
        id: issuer_key_id,
        ca_instance_id: "ca-e2.4",
        algorithm: "ECC-P256",
        status: "active",
        keystore_type: :software
      })

    {:ok, _} = Repo.insert(key)

    total = length(custodians)

    Enum.with_index(custodians, 1)
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

  defp seed_local_hsm_key(issuer_key_id) do
    key =
      IssuerKey.new(%{
        id: issuer_key_id,
        ca_instance_id: "ca-e2.4-hsm",
        algorithm: "ECC-P256",
        status: "active",
        keystore_type: :local_hsm,
        hsm_config: %{
          "library_path" => "/opt/softhsm/libsofthsm2.so",
          "slot_id" => 0,
          "pin" => "0000",
          "key_label" => "test-key"
        }
      })

    {:ok, _} = Repo.insert(key)
    key
  end

  # ---------------------------------------------------------------------------
  # Test 1: LocalHsmAdapter.authorize_session is deterministic
  # Calling with the same tokens twice → identical handle (same PIN)
  # ---------------------------------------------------------------------------

  test "LocalHsmAdapter.authorize_session returns same handle on retry (deterministic)", %{ka: _ka} do
    key_id = PkiMnesia.Id.generate()
    _key = seed_local_hsm_key(key_id)

    auth_tokens = ["pw-alice", "pw-bob", "pw-charlie"]

    assert {:ok, handle1} = LocalHsmAdapter.authorize_session(key_id, auth_tokens)
    assert {:ok, handle2} = LocalHsmAdapter.authorize_session(key_id, auth_tokens)

    assert handle1 == handle2
    assert handle1.type == :softhsm
    assert is_binary(handle1.pin)
    assert byte_size(handle1.pin) == 16
    assert handle1.key_id == key_id
  end

  test "LocalHsmAdapter.authorize_session PIN is order-independent (sorted tokens)", %{ka: _ka} do
    key_id = PkiMnesia.Id.generate()
    _key = seed_local_hsm_key(key_id)

    tokens_a = ["pw-charlie", "pw-alice", "pw-bob"]
    tokens_b = ["pw-alice", "pw-bob", "pw-charlie"]

    assert {:ok, h1} = LocalHsmAdapter.authorize_session(key_id, tokens_a)
    assert {:ok, h2} = LocalHsmAdapter.authorize_session(key_id, tokens_b)

    assert h1.pin == h2.pin
  end

  test "Dispatcher.authorize_session routes :local_hsm to LocalHsmAdapter", %{ka: _ka} do
    key_id = PkiMnesia.Id.generate()
    _key = seed_local_hsm_key(key_id)

    assert {:ok, handle} = Dispatcher.authorize_session(key_id, ["token-1", "token-2"])
    assert handle.type == :softhsm
    assert handle.key_id == key_id
  end

  test "Dispatcher.authorize_session routes :software to SoftwareAdapter", %{ka: _ka} do
    key_id = PkiMnesia.Id.generate()

    key =
      IssuerKey.new(%{
        id: key_id,
        ca_instance_id: "ca-sw",
        algorithm: "ECC-P256",
        status: "active",
        keystore_type: :software
      })

    {:ok, _} = Repo.insert(key)

    assert {:ok, handle} = Dispatcher.authorize_session(key_id, ["token-material"])
    assert handle.type == :software
    assert handle.key_material == "token-material"
    assert handle.key_id == key_id
  end

  # ---------------------------------------------------------------------------
  # Test 2: ActivationCeremony full flow via Dispatcher.authorize_session path
  # start → 2× submit_auth → lease active
  # ---------------------------------------------------------------------------

  test "ActivationCeremony: start → 2 submit_auth → lease active (Dispatcher.authorize_session path)",
       %{ka: ka} do
    key_id = PkiMnesia.Id.generate()
    custodians = [{"Alice", "pw-alice"}, {"Bob", "pw-bob"}, {"Charlie", "pw-charlie"}]
    seed_software_key(key_id, custodians, 2)

    # Start the session
    assert {:ok, session} = ActivationCeremony.start(key_id, key_activation: ka)
    assert session.status == "awaiting_custodians"

    # First custodian — threshold not met yet
    assert {:ok, s1} = ActivationCeremony.submit_auth(session.id, "Alice", "pw-alice", key_activation: ka)
    assert s1.status == "awaiting_custodians"
    assert length(s1.authenticated_custodians) == 1

    # Second custodian — threshold met, Dispatcher.authorize_session called internally
    assert {:ok, :lease_granted} =
             ActivationCeremony.submit_auth(session.id, "Bob", "pw-bob", key_activation: ka)

    # Lease must now be active in KeyActivation
    assert KeyActivation.is_active?(ka, key_id)

    # Session persisted as lease_active
    assert {:ok, final} = Repo.get(PkiMnesia.Structs.ActivationSession, session.id)
    assert final.status == "lease_active"
    assert length(final.authenticated_custodians) == 2
    assert not is_nil(final.completed_at)
  end

  test "SoftwareAdapter.authorize_session returns compat handle with first token", %{ka: _ka} do
    key_id = PkiMnesia.Id.generate()
    tokens = ["key-material-bytes", "second-token"]

    assert {:ok, handle} = SoftwareAdapter.authorize_session(key_id, tokens)
    assert handle.type == :software
    assert handle.key_material == "key-material-bytes"
    assert handle.key_id == key_id
  end

  test "Dispatcher.authorize_session returns :issuer_key_not_found for missing key", %{ka: _ka} do
    assert {:error, :issuer_key_not_found} =
             Dispatcher.authorize_session("nonexistent-key-id", ["token"])
  end
end
