defmodule PkiRaEngine.CsrProcessor do
  @moduledoc "Processes approved CSRs by forwarding them to CA for signing. Polls periodically."
  use GenServer

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: opts[:name] || __MODULE__)

  def init(opts) do
    interval = opts[:interval_ms] || 60_000
    Process.send_after(self(), :process_approved, interval)
    {:ok, %{interval: interval}}
  end

  def handle_info(:process_approved, state) do
    # Find approved CSRs and forward to CA signing
    case PkiMnesia.Repo.where(PkiMnesia.Structs.CsrRequest, fn c -> c.status == "approved" end) do
      {:ok, csrs} ->
        Enum.each(csrs, fn csr ->
          PkiRaEngine.CsrValidation.forward_to_ca(csr.id)
        end)
      {:error, _} -> :ok
    end
    Process.send_after(self(), :process_approved, state.interval)
    {:noreply, state}
  end
end
