defmodule PkiValidation.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    if Application.get_env(:pki_validation, :start_application, true) do
      # Standalone mode: pki_validation owns its own supervisor. The HTTP
      # listener + CrlPublisher are children of PkiValidation.Supervisor.
      PkiValidation.Supervisor.start_link([])
    else
      # Per-tenant mode: pki_tenant owns PkiValidation.Supervisor; this
      # app just needs to boot so its modules are loaded. Start an empty
      # supervisor without registering the named supervisor.
      Supervisor.start_link([], strategy: :one_for_one)
    end
  end
end
