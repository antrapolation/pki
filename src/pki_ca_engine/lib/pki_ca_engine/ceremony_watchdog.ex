defmodule PkiCaEngine.CeremonyWatchdog do
  @moduledoc "Expires key ceremonies that exceed their time window."
  use GenServer

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: opts[:name] || __MODULE__)

  def init(opts) do
    interval = opts[:interval_ms] || 60_000
    Process.send_after(self(), :check_expired, interval)
    {:ok, %{interval: interval}}
  end

  def handle_info(:check_expired, state) do
    now = DateTime.utc_now()
    case PkiMnesia.Repo.where(PkiMnesia.Structs.KeyCeremony, fn c ->
      c.status == "preparing" and c.window_expires_at != nil and DateTime.compare(c.window_expires_at, now) == :lt
    end) do
      {:ok, expired} ->
        Enum.each(expired, fn ceremony ->
          PkiMnesia.Repo.update(ceremony, %{status: "expired", updated_at: now |> DateTime.truncate(:second)})
        end)
      {:error, _} -> :ok
    end
    Process.send_after(self(), :check_expired, state.interval)
    {:noreply, state}
  end
end
