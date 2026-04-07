defmodule PkiValidation.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children =
      [
        PkiValidation.Repo,
        PkiValidation.SigningKeyStore,
        PkiValidation.OcspCache,
        PkiValidation.CrlPublisher
      ] ++ http_children()

    opts = [strategy: :one_for_one, name: PkiValidation.Supervisor]
    Supervisor.start_link(children, opts)
  end

  defp http_children do
    if Application.get_env(:pki_validation, :http)[:start] do
      port = Application.get_env(:pki_validation, :http)[:port] || 4005

      [
        {Plug.Cowboy, plug: PkiValidation.Api.Router, scheme: :http, port: port}
      ]
    else
      []
    end
  end
end
