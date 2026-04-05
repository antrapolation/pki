defmodule PkiCaEngine.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children =
      [
        PkiCaEngine.Repo,
        %{id: :ceremony_pid_registry, start: {Agent, :start_link, [fn -> %{} end, [name: :ceremony_pid_registry]]}},
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

  defp maybe_dev_auto_activate_keys do
    if Application.get_env(:pki_ca_engine, :dev_auto_activate_keys, false) do
      Task.start(fn ->
        Process.sleep(5_000)
        require Logger
        Logger.info("[CA Engine] Dev auto-activating issuer keys...")

        try do
          import Ecto.Query
          alias PkiCaEngine.Schema.IssuerKey

          keys = PkiCaEngine.Repo.all(from k in IssuerKey, where: k.status == "active")

          for key <- keys do
            unless PkiCaEngine.KeyActivation.is_active?(key.id) do
              rsa_key = X509.PrivateKey.new_rsa(2048)
              rsa_der = X509.PrivateKey.to_der(rsa_key)
              PkiCaEngine.KeyActivation.dev_activate(key.id, rsa_der)
              Logger.info("[CA Engine] Dev-activated key #{key.key_alias} (#{key.id})")
            end
          end
        rescue
          e -> Logger.warning("[CA Engine] Dev auto-activate failed: #{Exception.message(e)}")
        end
      end)
    end
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
