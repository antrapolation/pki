defmodule PkiValidation.Supervisor do
  @moduledoc """
  Top-level supervisor for the pki_validation engine.

  Children:
  - CrlPublisher — GenServer that periodically generates the CRL from Mnesia

  OCSP is stateless (direct Mnesia lookups) so it needs no supervised process.
  The SigningKeyStore is eliminated — signing now goes through
  PkiCaEngine.KeyActivation directly.
  """

  use Supervisor

  def start_link(opts \\ []) do
    Supervisor.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    children = [
      {PkiValidation.CrlPublisher, []}
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end
end
