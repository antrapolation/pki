defmodule PkiRaEngine.CsrProcessorTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.{TestHelper, Repo}
  alias PkiMnesia.Structs.CsrRequest
  alias PkiRaEngine.CsrProcessor

  setup do
    dir = TestHelper.setup_mnesia()
    {:ok, pid} = CsrProcessor.start_link(name: :"csr_processor_test_#{System.unique_integer()}", interval_ms: :timer.hours(24))
    on_exit(fn ->
      if Process.alive?(pid), do: GenServer.stop(pid)
      TestHelper.teardown_mnesia(dir)
    end)
    %{pid: pid}
  end

  test "starts without error", %{pid: pid} do
    assert Process.alive?(pid)
  end

  test "handle_info :process_approved with no approved CSRs does not crash", %{pid: pid} do
    send(pid, :process_approved)
    Process.sleep(50)
    assert Process.alive?(pid)
  end

  test "handle_info :process_approved with approved CSR attempts forwarding", %{pid: pid} do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    csr = CsrRequest.new(%{
      csr_pem: "-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----",
      cert_profile_id: "prof-1",
      subject_dn: "CN=test.example.com",
      status: "approved",
      submitted_at: now
    })
    {:ok, _} = Repo.insert(csr)

    send(pid, :process_approved)
    Process.sleep(100)

    # Process stays alive regardless of CA availability
    assert Process.alive?(pid)
  end
end
