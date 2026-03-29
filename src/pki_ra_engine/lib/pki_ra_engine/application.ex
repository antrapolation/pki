defmodule PkiRaEngine.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children =
      [
        {Hammer.Supervisor, [strategy: :one_for_all]},
        PkiRaEngine.Repo,
        PkiRaEngine.CaEngineConfig
      ] ++ http_children()

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: PkiRaEngine.Supervisor]
    Supervisor.start_link(children, opts)
  end

  defp http_children do
    if Application.get_env(:pki_ra_engine, :start_http, false) do
      [{Plug.Cowboy, scheme: :http, plug: PkiRaEngine.Api.Router, options: [port: 4003]}]
    else
      []
    end
  end
end
