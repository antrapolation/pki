defmodule PkiValidation.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children =
      if Application.get_env(:pki_validation, :start_application, true) do
        [
          PkiValidation.CrlPublisher
        ] ++ http_children()
      else
        []
      end

    if Application.get_env(:pki_validation, :start_application, true) do
      opts = [strategy: :one_for_one, name: PkiValidation.Supervisor]
      Supervisor.start_link(children, opts)
    else
      # Don't register the supervisor name — pki_tenant will start it instead
      Supervisor.start_link([], strategy: :one_for_one)
    end
  end

  defp http_children do
    if Application.get_env(:pki_validation, :http, [])[:start] do
      port = Application.get_env(:pki_validation, :http)[:port] || 4005

      [
        {Plug.Cowboy, plug: PkiValidation.Api.Router, scheme: :http, port: port}
      ]
    else
      []
    end
  end
end
