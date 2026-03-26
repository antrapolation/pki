defmodule PkiCaEngine.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children =
      [
        PkiCaEngine.Repo,
        {PkiCaEngine.KeyActivation,
         name: PkiCaEngine.KeyActivation,
         timeout_ms: Application.get_env(:pki_ca_engine, :key_activation_timeout_ms, 3_600_000)},
        {DynamicSupervisor, strategy: :one_for_one, name: PkiCaEngine.EngineSupervisor}
      ] ++ http_children()

    opts = [strategy: :one_for_one, name: PkiCaEngine.Supervisor]
    result = Supervisor.start_link(children, opts)
    ensure_default_instance()
    result
  end

  defp ensure_default_instance do
    import Ecto.Query
    alias PkiCaEngine.Schema.CaInstance

    case PkiCaEngine.Repo.one(
           from(i in CaInstance, where: i.name == "default", limit: 1)
         ) do
      nil ->
        %CaInstance{}
        |> CaInstance.changeset(%{name: "default", status: "active", created_by: "system"})
        |> PkiCaEngine.Repo.insert!()

      _exists ->
        :ok
    end
  rescue
    # DB not ready yet (migrations not run) — skip silently
    _ -> :ok
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
