defmodule PkiCaEngine.KeyActivationTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.{TestHelper, Repo}
  alias PkiMnesia.Structs.ThresholdShare
  alias PkiCaEngine.KeyActivation

  setup do
    dir = TestHelper.setup_mnesia()

    {:ok, pid} = KeyActivation.start_link(name: :test_ka, timeout_ms: 60_000)

    on_exit(fn ->
      if Process.alive?(pid), do: GenServer.stop(pid)
      TestHelper.teardown_mnesia(dir)
    end)

    %{ka: :test_ka}
  end

  test "get_active_key returns error when key not activated", %{ka: ka} do
    assert {:error, :not_active} = KeyActivation.get_active_key(ka, "some-key-id")
  end

  test "is_active? returns false for non-activated key", %{ka: ka} do
    refute KeyActivation.is_active?(ka, "some-key-id")
  end

  test "dev_activate injects a key directly", %{ka: ka} do
    Application.put_env(:pki_ca_engine, :allow_dev_activate, true)

    key_id = "test-key-1"
    priv = :crypto.strong_rand_bytes(32)

    assert {:ok, :dev_activated} = KeyActivation.dev_activate(ka, key_id, priv)
    assert KeyActivation.is_active?(ka, key_id)
    assert {:ok, ^priv} = KeyActivation.get_active_key(ka, key_id)

    Application.put_env(:pki_ca_engine, :allow_dev_activate, false)
  end

  test "dev_activate rejects when allow_dev_activate flag is false", %{ka: ka} do
    Application.put_env(:pki_ca_engine, :allow_dev_activate, false)

    priv = :crypto.strong_rand_bytes(32)

    assert {:error, :not_available_in_production} =
             KeyActivation.dev_activate(ka, "gated-key", priv)

    refute KeyActivation.is_active?(ka, "gated-key")
  end

  test "deactivate removes an active key", %{ka: ka} do
    Application.put_env(:pki_ca_engine, :allow_dev_activate, true)

    key_id = "test-key-2"
    priv = :crypto.strong_rand_bytes(32)
    KeyActivation.dev_activate(ka, key_id, priv)

    assert :ok = KeyActivation.deactivate(ka, key_id)
    refute KeyActivation.is_active?(ka, key_id)

    Application.put_env(:pki_ca_engine, :allow_dev_activate, false)
  end

  # G1 — Timeout eviction test
  test "key is evicted after timeout", %{ka: ka} do
    GenServer.stop(ka)
    {:ok, ka2} = KeyActivation.start_link(name: :ka_timeout_test, timeout_ms: 50, allow_dev_activate: true)
    Application.put_env(:pki_ca_engine, :allow_dev_activate, true)

    key_id = PkiMnesia.Id.generate()
    {:ok, :dev_activated} = KeyActivation.dev_activate(ka2, key_id, "secret")
    assert KeyActivation.is_active?(ka2, key_id) == true

    Process.sleep(100)
    assert KeyActivation.is_active?(ka2, key_id) == false

    Application.put_env(:pki_ca_engine, :allow_dev_activate, false)
    GenServer.stop(ka2)
  end

  # G2 — Wrong password returns decryption_failed
  test "submit_share with wrong password returns decryption_failed", %{ka: ka} do
    key_id = PkiMnesia.Id.generate()
    {:ok, encrypted} = PkiCaEngine.KeyCeremony.ShareEncryption.encrypt_share("share-data", "correct-password")
    salt = :crypto.strong_rand_bytes(16)
    hash = :crypto.pbkdf2_hmac(:sha256, "correct-password", salt, 100_000, 32)

    share = ThresholdShare.new(%{
      issuer_key_id: key_id,
      custodian_name: "alice",
      share_index: 1,
      encrypted_share: encrypted,
      password_hash: salt <> hash,
      min_shares: 1,
      total_shares: 1
    })
    {:ok, _} = Repo.insert(share)

    assert {:error, :decryption_failed} = KeyActivation.submit_share(ka, key_id, "alice", "wrong-password")
    assert KeyActivation.is_active?(ka, key_id) == false
  end

  # G3 — Replay attack: same custodian cannot submit share twice
  test "same custodian cannot submit share twice", %{ka: ka} do
    key_id = PkiMnesia.Id.generate()
    {:ok, encrypted} = PkiCaEngine.KeyCeremony.ShareEncryption.encrypt_share("share-1", "pass1")
    salt = :crypto.strong_rand_bytes(16)
    hash = :crypto.pbkdf2_hmac(:sha256, "pass1", salt, 100_000, 32)

    share = ThresholdShare.new(%{
      issuer_key_id: key_id,
      custodian_name: "alice",
      share_index: 1,
      encrypted_share: encrypted,
      password_hash: salt <> hash,
      min_shares: 2,
      total_shares: 2
    })
    {:ok, _} = Repo.insert(share)

    assert {:ok, :share_accepted} = KeyActivation.submit_share(ka, key_id, "alice", "pass1")
    assert {:error, :already_submitted} = KeyActivation.submit_share(ka, key_id, "alice", "pass1")
  end
end
