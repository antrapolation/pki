defmodule PkiCaEngine.KeyActivationPropertyTest do
  use ExUnit.Case, async: false
  use ExUnitProperties

  alias PkiCaEngine.KeyActivation

  # Each property test spins up its own named GenServer so they don't collide.
  # We use System.unique_integer/1 to ensure unique names across concurrent runs.

  defp start_ka do
    name = :"ka_prop_#{System.unique_integer([:positive, :monotonic])}"
    {:ok, pid} = KeyActivation.start_link(name: name)
    {pid, name}
  end

  defp stop_ka(pid) do
    if Process.alive?(pid), do: GenServer.stop(pid)
  end

  # ----------------------------------------------------------------------------
  # Property 1: Lease never resurrects after expiry
  #
  # A lease created with ttl_seconds: 0 has its expires_at already in the past
  # (or exactly now) when activate/5 returns. lease_status must therefore report
  # active: false regardless of how many times it is queried.
  # ----------------------------------------------------------------------------
  property "lease never active after expiry (ttl_seconds: 0)" do
    check all key_id <- string(:alphanumeric, min_length: 1),
              max_runs: 20 do
      {pid, ka} = start_ka()

      try do
        handle = :crypto.strong_rand_bytes(16)
        {:ok, ^key_id} = KeyActivation.activate(ka, key_id, handle, ["custodian"], ttl_seconds: 0, max_ops: 100)

        # Query immediately — expiry is at or before this moment
        status = KeyActivation.lease_status(ka, key_id)
        assert status.active == false,
               "expected active: false for expired lease, got: #{inspect(status)}"

        # Querying again must not resurrect the lease
        status2 = KeyActivation.lease_status(ka, key_id)
        assert status2.active == false
      after
        stop_ka(pid)
      end
    end
  end

  # ----------------------------------------------------------------------------
  # Property 2: ops_remaining is monotonically non-increasing within a lease
  #
  # After a single with_lease call, ops_remaining must be strictly less than or
  # equal to (in practice, exactly one less than) the value before the call.
  # ----------------------------------------------------------------------------
  property "ops_remaining never increases within a lease" do
    check all ops <- integer(1..20),
              key_id <- string(:alphanumeric, min_length: 1),
              max_runs: 25 do
      {pid, ka} = start_ka()

      try do
        handle = :crypto.strong_rand_bytes(16)
        {:ok, ^key_id} = KeyActivation.activate(ka, key_id, handle, ["custodian"], max_ops: ops)

        ops_before = KeyActivation.lease_status(ka, key_id).ops_remaining
        assert ops_before == ops

        KeyActivation.with_lease(ka, key_id, fn _ -> :ok end)

        ops_after = KeyActivation.lease_status(ka, key_id).ops_remaining
        # ops_remaining must not have increased
        assert ops_after <= ops_before,
               "ops_remaining went from #{ops_before} to #{ops_after} — should be non-increasing"

        # And for a single call it must have decremented by exactly 1
        assert ops_after == ops_before - 1,
               "expected exactly one decrement: #{ops_before} -> #{ops_before - 1}, got #{ops_after}"
      after
        stop_ka(pid)
      end
    end
  end

  # ----------------------------------------------------------------------------
  # Property 3: Concurrent with_lease calls don't double-spend ops
  #
  # Fire `concurrency` Tasks in parallel. Because KeyActivation is a GenServer
  # its handle_call serialises every message, so exactly `concurrency` ops must
  # be consumed — no double-spending, no dropped decrements.
  # ----------------------------------------------------------------------------
  property "concurrent with_lease calls don't double-spend ops" do
    check all concurrency <- integer(2..8),
              key_id <- string(:alphanumeric, min_length: 1),
              max_runs: 15 do
      {pid, ka} = start_ka()

      try do
        # Give plenty of budget so we never hit exhaustion mid-test
        budget = concurrency * 4
        handle = :crypto.strong_rand_bytes(16)
        {:ok, ^key_id} = KeyActivation.activate(ka, key_id, handle, ["custodian"], max_ops: budget)

        initial = KeyActivation.lease_status(ka, key_id).ops_remaining
        assert initial == budget

        # Launch all tasks concurrently, then await all
        tasks =
          Enum.map(1..concurrency, fn _ ->
            Task.async(fn -> KeyActivation.with_lease(ka, key_id, fn _ -> :ok end) end)
          end)

        results = Enum.map(tasks, &Task.await(&1, 5_000))

        # Every call must have succeeded (none should hit exhaustion)
        assert Enum.all?(results, &match?({:ok, _}, &1)),
               "some concurrent with_lease calls failed unexpectedly: #{inspect(results)}"

        final = KeyActivation.lease_status(ka, key_id).ops_remaining
        assert final == initial - concurrency,
               "expected ops to drop by exactly #{concurrency} (from #{initial} to #{initial - concurrency}), got #{final}"
      after
        stop_ka(pid)
      end
    end
  end

  # ----------------------------------------------------------------------------
  # Property 4: Ops exhaustion is fail-closed and non-resurrect
  #
  # Once the last op is consumed the lease is exhausted and evicted (M7 change).
  # Every subsequent call to with_lease must return an error — not crash, not
  # return {:ok, _}, and not flip active back to true. After eviction the error
  # is :not_found (lease gone) rather than :ops_exhausted (M7 evicts on exhaustion).
  # ----------------------------------------------------------------------------
  property "ops exhaustion is fail-closed — subsequent calls always fail" do
    check all key_id <- string(:alphanumeric, min_length: 1),
              max_runs: 20 do
      {pid, ka} = start_ka()

      try do
        handle = :crypto.strong_rand_bytes(16)
        {:ok, ^key_id} = KeyActivation.activate(ka, key_id, handle, ["custodian"], max_ops: 1)

        # Consume the single allowed op
        assert {:ok, _} = KeyActivation.with_lease(ka, key_id, fn _ -> :ok end)

        # First call after exhaustion — lease is evicted, returns :not_found or :ops_exhausted
        result1 = KeyActivation.with_lease(ka, key_id, fn _ -> :ok end)
        assert match?({:error, _}, result1),
               "expected error after ops exhaustion, got: #{inspect(result1)}"

        # Second call after exhaustion — must also fail (non-resurrect invariant)
        result2 = KeyActivation.with_lease(ka, key_id, fn _ -> :ok end)
        assert match?({:error, _}, result2),
               "expected error on second post-exhaustion call, got: #{inspect(result2)}"

        # Lease status must reflect inactive state
        status = KeyActivation.lease_status(ka, key_id)
        assert status.active == false,
               "expected active: false after ops exhaustion, got: #{inspect(status)}"

        # After eviction ops_remaining is nil (lease gone) or 0; both mean exhausted.
        assert status.ops_remaining in [0, nil],
               "expected ops_remaining 0 or nil after exhaustion, got: #{status.ops_remaining}"
      after
        stop_ka(pid)
      end
    end
  end

  # Helper so we don't depend on Mnesia in these tests — the GenServer stores
  # everything in memory, so no Mnesia setup is needed for KeyActivation alone.
  setup do
    # Ensure PkiMnesia is not required for property tests (KeyActivation's
    # in-memory path doesn't touch Mnesia; submit_share does, but we don't
    # exercise that here).
    :ok
  end
end
