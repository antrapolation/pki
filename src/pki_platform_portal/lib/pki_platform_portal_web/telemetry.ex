defmodule PkiPlatformPortalWeb.Telemetry do
  use Supervisor
  import Telemetry.Metrics

  def start_link(arg) do
    Supervisor.start_link(__MODULE__, arg, name: __MODULE__)
  end

  @impl true
  def init(_arg) do
    children = [
      {:telemetry_poller, measurements: periodic_measurements(), period: 10_000}
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end

  def metrics do
    [
      summary("phoenix.endpoint.start.system_time",
        unit: {:native, :millisecond}
      ),
      summary("phoenix.endpoint.stop.duration",
        unit: {:native, :millisecond}
      ),
      summary("phoenix.router_dispatch.start.system_time",
        tags: [:route],
        unit: {:native, :millisecond}
      ),
      summary("phoenix.router_dispatch.stop.duration",
        tags: [:route],
        unit: {:native, :millisecond}
      ),
      summary("phoenix.socket_connected.duration",
        unit: {:native, :millisecond}
      ),
      sum("phoenix.socket_drain.count"),
      summary("vm.memory.total", unit: {:byte, :kilobyte}),
      summary("vm.total_run_queue_lengths.total"),
      summary("vm.total_run_queue_lengths.cpu"),
      summary("vm.total_run_queue_lengths.io"),

      # HSM session / key-activation lease metrics
      last_value("pki_hsm_session_active",
        event_name: [:pki_ca_engine, :key_activation, :lease],
        measurement: fn m, _meta ->
          if m.ops_remaining > 0 and Map.get(m, :expires_in, 1) > 0, do: 1, else: 0
        end,
        tags: [:key_id]
      ),
      last_value("pki_hsm_session_ops_remaining",
        event_name: [:pki_ca_engine, :key_activation, :lease],
        measurement: :ops_remaining,
        tags: [:key_id]
      ),
      last_value("pki_hsm_session_expires_in_seconds",
        event_name: [:pki_ca_engine, :key_activation, :lease],
        measurement: fn m, _meta -> Map.get(m, :expires_in, 0) end,
        tags: [:key_id]
      )
    ]
  end

  defp periodic_measurements do
    []
  end
end
