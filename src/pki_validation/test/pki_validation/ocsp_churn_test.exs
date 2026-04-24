defmodule PkiValidation.OcspChurnTest do
  @moduledoc """
  Nightly load test for OCSP status lookups.

  Seeds N cert statuses, then drives high-concurrency `check_status/1`
  calls through `Task.async_stream`. Samples `:erlang.memory(:total)`
  and process count before/after (post-GC) and fails if either grew
  past the threshold — catches both memory leaks and process-leak
  patterns (e.g. unlinked GenServers, unstopped Postgrex pools).

  Excluded from the per-PR matrix via `@tag :nightly`. Runs from the
  nightly GitHub Actions workflow.
  """
  use ExUnit.Case, async: false

  alias PkiMnesia.{TestHelper, Repo}
  alias PkiMnesia.Structs.CertificateStatus
  alias PkiValidation.OcspResponder

  @moduletag :nightly
  @moduletag timeout: 300_000

  @seed_count 1_000
  @concurrency 50
  @iterations 10_000
  # GitHub Actions runners have noisy neighbors and cold caches on first
  # hit. Allow 30% growth as the false-positive buffer. Real leaks scale
  # linearly with iterations (a 1KB/call leak at 10k iterations = 10MB
  # growth, way past this floor).
  @memory_growth_ratio 1.3
  @process_growth_abs 50

  setup do
    dir = TestHelper.setup_mnesia()
    on_exit(fn -> TestHelper.teardown_mnesia(dir) end)
    :ok
  end

  test "high-concurrency OCSP lookups don't leak memory or processes" do
    seed_cert_statuses(@seed_count)
    serials = for i <- 1..@seed_count, do: "serial-#{i}"

    {mem_before, proc_before} = snapshot()

    results =
      1..@iterations
      |> Stream.map(fn i -> Enum.at(serials, rem(i, @seed_count)) end)
      |> Task.async_stream(
        fn serial -> OcspResponder.check_status(serial) end,
        max_concurrency: @concurrency,
        ordered: false,
        timeout: 30_000
      )
      |> Enum.to_list()

    # Invariant: every call returned a well-formed {:ok, %{status: _}} tuple.
    # Catches races that manifest as crashes, nil map values, or :exit tuples.
    assert Enum.all?(results, &match?({:ok, {:ok, %{status: s}}} when is_binary(s), &1)),
           "Found non-conforming results under concurrent load — likely a race condition"

    {mem_after, proc_after} = snapshot()

    mem_growth = mem_after / mem_before
    proc_growth = proc_after - proc_before

    IO.puts("""
    [ocsp_churn] iterations=#{@iterations} concurrency=#{@concurrency}
    [ocsp_churn] memory: #{mb(mem_before)} → #{mb(mem_after)} (x#{Float.round(mem_growth, 2)})
    [ocsp_churn] processes: #{proc_before} → #{proc_after} (+#{proc_growth})
    """)

    assert mem_growth < @memory_growth_ratio,
           "Memory grew #{Float.round(mem_growth, 2)}x (#{mb(mem_before)} → #{mb(mem_after)}), " <>
             "threshold #{@memory_growth_ratio}x — possible leak"

    assert proc_growth < @process_growth_abs,
           "Process count grew by #{proc_growth} (#{proc_before} → #{proc_after}), " <>
             "threshold #{@process_growth_abs} — possible process leak"
  end

  defp seed_cert_statuses(count) do
    now = DateTime.utc_now()
    not_after = DateTime.add(now, 365 * 24 * 3600, :second)

    for i <- 1..count do
      cs =
        CertificateStatus.new(%{
          serial_number: "serial-#{i}",
          status: if(rem(i, 10) == 0, do: "revoked", else: "good"),
          not_after: not_after,
          issuer_key_id: "test-issuer"
        })

      {:ok, _} = Repo.insert(cs)
    end
  end

  defp snapshot do
    # Two rounds of GC on every process — single pass leaves some garbage
    # in young generations.
    for _ <- 1..2 do
      Enum.each(Process.list(), &:erlang.garbage_collect/1)
    end

    {:erlang.memory(:total), length(Process.list())}
  end

  defp mb(bytes), do: "#{Float.round(bytes / 1_048_576, 1)}MB"
end
