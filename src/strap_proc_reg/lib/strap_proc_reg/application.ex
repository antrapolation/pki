defmodule StrapProcReg.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false
  alias StrapProcReg.RegStore.EtsRegStore

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      # Starts a worker by calling: StrapProcReg.Worker.start_link(arg)
      # {StrapProcReg.Worker, arg}
      {EtsRegStore, :ets_strap_proc_reg_store},
      # (%{heartbeat_period: 5_000})}
      {StrapProcReg, StrapProcReg.new()}
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: StrapProcReg.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
