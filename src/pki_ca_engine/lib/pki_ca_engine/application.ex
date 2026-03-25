defmodule PkiCaEngine.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    crypto_adapter_mod =
      Application.get_env(:pki_ca_engine, :crypto_adapter, PkiCaEngine.KeyCeremony.DefaultCryptoAdapter)

    children =
      [
        PkiCaEngine.Repo,
        {PkiCaEngine.KeyActivation,
         name: PkiCaEngine.KeyActivation,
         crypto_adapter: struct(crypto_adapter_mod),
         timeout_ms: Application.get_env(:pki_ca_engine, :key_activation_timeout_ms, 3_600_000)},
        {DynamicSupervisor, strategy: :one_for_one, name: PkiCaEngine.EngineSupervisor}
      ] ++ http_children()

    opts = [strategy: :one_for_one, name: PkiCaEngine.Supervisor]
    Supervisor.start_link(children, opts)
  end

  defp http_children do
    if Application.get_env(:pki_ca_engine, :start_http, false) do
      port = Application.get_env(:pki_ca_engine, :http_port, 4001)
      [{Plug.Cowboy, scheme: :http, plug: PkiCaEngine.Api.Router, options: [port: port]}]
    else
      []
    end
  end
end
