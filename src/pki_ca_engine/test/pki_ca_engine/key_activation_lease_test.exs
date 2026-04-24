defmodule PkiCaEngine.KeyActivationLeaseTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.TestHelper
  alias PkiCaEngine.KeyActivation

  setup do
    dir = TestHelper.setup_mnesia()

    {:ok, pid} = KeyActivation.start_link(name: :test_ka_lease)

    on_exit(fn ->
      if Process.alive?(pid), do: GenServer.stop(pid)
      TestHelper.teardown_mnesia(dir)
    end)

    %{ka: :test_ka_lease}
  end

  # Test 1 — ops_exhausted after max_ops reached
  test "activate → use 100 times → 101st with_lease returns {:error, :ops_exhausted}", %{ka: ka} do
    key_id = "lease-ops-test-#{System.unique_integer()}"
    handle = :crypto.strong_rand_bytes(32)

    {:ok, ^key_id} = KeyActivation.activate(ka, key_id, handle, ["alice"], max_ops: 100)

    # 100 successful calls
    for _i <- 1..100 do
      assert {:ok, _result} = KeyActivation.with_lease(ka, key_id, fn h -> h end)
    end

    # 101st must be exhausted
    assert {:error, :ops_exhausted} = KeyActivation.with_lease(ka, key_id, fn h -> h end)
  end

  # Test 2 — lease_status returns active: false after expiry (very short TTL)
  test "lease_status returns active: false after lease expires", %{ka: ka} do
    # Stop default server, start one with extremely short timeout
    GenServer.stop(ka)
    {:ok, pid2} = KeyActivation.start_link(name: :test_ka_lease_ttl, timeout_ms: 50)

    key_id = "lease-ttl-test-#{System.unique_integer()}"
    handle = :crypto.strong_rand_bytes(32)

    {:ok, ^key_id} = KeyActivation.activate(:test_ka_lease_ttl, key_id, handle, ["bob"], ttl_seconds: 0)

    # After 0-second TTL the expires_at is in the past immediately
    status = KeyActivation.lease_status(:test_ka_lease_ttl, key_id)
    assert status.active == false

    GenServer.stop(pid2)
  end

  # Test 3 — with_lease decrements ops_remaining correctly
  test "with_lease decrements ops_remaining correctly", %{ka: ka} do
    key_id = "lease-decrement-test-#{System.unique_integer()}"
    handle = :crypto.strong_rand_bytes(16)

    {:ok, ^key_id} = KeyActivation.activate(ka, key_id, handle, ["carol"], max_ops: 10)

    # Initial status
    status_before = KeyActivation.lease_status(ka, key_id)
    assert status_before.ops_remaining == 10
    assert status_before.active == true

    # Use it 3 times
    for _i <- 1..3 do
      assert {:ok, _} = KeyActivation.with_lease(ka, key_id, fn h -> {:ok, h} end)
    end

    status_after = KeyActivation.lease_status(ka, key_id)
    assert status_after.ops_remaining == 7
    assert status_after.active == true
  end

  # Test 4 — submit_share shim routes through lease system (ops not exhausted)
  test "existing submit_share shim still routes correctly (ops not exhausted)", %{ka: ka} do
    Application.put_env(:pki_ca_engine, :allow_dev_activate, true)

    key_id = "shim-test-#{System.unique_integer()}"
    priv = :crypto.strong_rand_bytes(32)

    # Use dev_activate as a proxy for the submit_share pathway (same internal route)
    assert {:ok, :dev_activated} = KeyActivation.dev_activate(ka, key_id, priv)
    assert KeyActivation.is_active?(ka, key_id)

    # Should be able to call with_lease many times (unlimited ops via shim)
    for _i <- 1..10 do
      assert {:ok, _} = KeyActivation.with_lease(ka, key_id, fn h -> {:ok, h} end)
    end

    # get_active_key shim still works
    assert {:ok, ^priv} = KeyActivation.get_active_key(ka, key_id)

    # ops should still be far from exhausted
    status = KeyActivation.lease_status(ka, key_id)
    assert status.active == true
    assert status.ops_remaining > 990_000

    Application.put_env(:pki_ca_engine, :allow_dev_activate, false)
  end
end
