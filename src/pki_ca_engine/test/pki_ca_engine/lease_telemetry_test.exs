defmodule PkiCaEngine.LeaseTelemetryTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.TestHelper
  alias PkiCaEngine.KeyActivation

  @event [:pki_ca_engine, :key_activation, :lease]

  setup_all do
    Application.ensure_all_started(:telemetry)
    :ok
  end

  setup do
    dir = TestHelper.setup_mnesia()

    {:ok, pid} = KeyActivation.start_link(name: :test_ka_telemetry)

    on_exit(fn ->
      :telemetry.detach("test-telemetry-activate")
      :telemetry.detach("test-telemetry-used")
      :telemetry.detach("test-telemetry-expired")
      if Process.alive?(pid), do: GenServer.stop(pid)
      TestHelper.teardown_mnesia(dir)
    end)

    %{ka: :test_ka_telemetry}
  end

  test "emits telemetry on activate", %{ka: ka} do
    test_pid = self()

    :telemetry.attach(
      "test-telemetry-activate",
      @event,
      fn _name, measurements, metadata, _config ->
        send(test_pid, {:telemetry, measurements, metadata})
      end,
      nil
    )

    key_id = "telem-activate-#{System.unique_integer()}"
    handle = :crypto.strong_rand_bytes(16)

    {:ok, ^key_id} = KeyActivation.activate(ka, key_id, handle, ["alice"], max_ops: 5, ttl_seconds: 300)

    assert_receive {:telemetry, measurements, metadata}, 1_000

    assert metadata.event == :activated
    assert metadata.key_id == key_id
    assert measurements.ops_remaining == 5
    assert measurements.expires_in == 300
  end

  test "emits telemetry on with_lease use", %{ka: ka} do
    test_pid = self()

    key_id = "telem-use-#{System.unique_integer()}"
    handle = :crypto.strong_rand_bytes(16)

    {:ok, ^key_id} = KeyActivation.activate(ka, key_id, handle, ["bob"], max_ops: 10, ttl_seconds: 300)

    # Drain the :activated event before attaching for :used
    receive do
      {:telemetry, _, _} -> :ok
    after
      50 -> :ok
    end

    :telemetry.attach(
      "test-telemetry-used",
      @event,
      fn _name, measurements, metadata, _config ->
        send(test_pid, {:telemetry, measurements, metadata})
      end,
      nil
    )

    {:ok, _} = KeyActivation.with_lease(ka, key_id, fn h -> h end)

    assert_receive {:telemetry, measurements, metadata}, 1_000

    assert metadata.event == :used
    assert metadata.key_id == key_id
    # started at 10, used once → 9 remaining
    assert measurements.ops_remaining == 9
  end

  test "emits telemetry on lease expiry via timeout", %{ka: ka} do
    test_pid = self()

    # Stop the default server; start one with a very short timer
    GenServer.stop(ka)
    {:ok, _pid2} = KeyActivation.start_link(name: :test_ka_telemetry_expiry, timeout_ms: 50)

    key_id = "telem-expiry-#{System.unique_integer()}"
    handle = :crypto.strong_rand_bytes(16)

    {:ok, ^key_id} = KeyActivation.activate(
      :test_ka_telemetry_expiry,
      key_id,
      handle,
      ["carol"],
      ttl_seconds: 1
    )

    :telemetry.attach(
      "test-telemetry-expired",
      @event,
      fn _name, measurements, metadata, _config ->
        send(test_pid, {:telemetry, measurements, metadata})
      end,
      nil
    )

    # Force expiry by calling with_lease after TTL has passed
    # (ttl_seconds: 1 means expires_at is 1s in the future; we directly
    # trigger the timeout path by using 0-second TTL activation)
    GenServer.stop(:test_ka_telemetry_expiry)
    {:ok, _pid3} = KeyActivation.start_link(name: :test_ka_telemetry_expiry2)

    key_id2 = "telem-expiry2-#{System.unique_integer()}"

    {:ok, ^key_id2} = KeyActivation.activate(
      :test_ka_telemetry_expiry2,
      key_id2,
      handle,
      ["dave"],
      ttl_seconds: 0
    )

    # with_lease triggers the expired branch → evict_lease → telemetry
    {:error, :lease_expired} = KeyActivation.with_lease(:test_ka_telemetry_expiry2, key_id2, fn h -> h end)

    assert_receive {:telemetry, measurements, metadata}, 1_000

    # Filter for :expired event (activated event fires first, but we catch first matching)
    expired_messages =
      Stream.repeatedly(fn ->
        receive do
          {:telemetry, m, md} -> {m, md}
        after
          100 -> nil
        end
      end)
      |> Stream.take_while(& &1 != nil)
      |> Enum.to_list()

    all_events = [{measurements, metadata} | expired_messages]

    expired = Enum.find(all_events, fn {_m, md} -> md.event == :expired end)
    assert expired != nil, "Expected :expired telemetry event"
    {exp_measurements, exp_metadata} = expired
    assert exp_metadata.key_id == key_id2
    assert exp_measurements.ops_remaining == 0
    assert exp_measurements.expires_in == 0

    GenServer.stop(:test_ka_telemetry_expiry2)
  end
end
