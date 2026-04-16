defmodule PkiCaEngine.EngineSupervisor do
  @moduledoc """
  Supervises the CA engine processes (KeyActivation GenServer).
  """
  use Supervisor

  def start_link(opts \\ []) do
    Supervisor.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    children = [
      {PkiCaEngine.KeyActivation, []}
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end
end
