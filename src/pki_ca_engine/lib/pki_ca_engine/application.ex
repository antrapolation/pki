defmodule PkiCaEngine.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    assert_dev_activate_safe!()

    children =
      if Application.get_env(:pki_ca_engine, :start_application, true) do
        [
          PkiCaEngine.Repo,
          {PkiCaEngine.CeremonyRegistry, name: :ceremony_pid_registry},
          {PkiCaEngine.KeyActivation,
           name: PkiCaEngine.KeyActivation,
           timeout_ms: Application.get_env(:pki_ca_engine, :key_activation_timeout_ms, 3_600_000)},
          {DynamicSupervisor, strategy: :one_for_one, name: PkiCaEngine.EngineSupervisor}
        ] ++ http_children()
      else
        []
      end

    result = if Application.get_env(:pki_ca_engine, :start_application, true) do
      opts = [strategy: :rest_for_one, name: PkiCaEngine.Supervisor]
      Supervisor.start_link(children, opts)
    else
      Supervisor.start_link([], strategy: :one_for_one)
    end

    if Application.get_env(:pki_ca_engine, :start_application, true) do
      ensure_default_instance()
    end

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

  @doc false
  def assert_dev_activate_safe! do
    # Prefer pki_ca_engine's own env config (set by config.exs from
    # config_env/0). Fall back to the umbrella's :pki_system, :env when
    # running inside the root project; default to :prod when neither is
    # set so that an unconfigured deploy fails closed.
    compile_env =
      Application.get_env(:pki_ca_engine, :env) ||
        Application.get_env(:pki_system, :env, :prod)

    runtime_flag = Application.get_env(:pki_ca_engine, :allow_dev_activate, false)

    case check_dev_activate_safe(compile_env, runtime_flag) do
      :ok -> :ok
      {:unsafe, message} -> raise message
    end
  end

  # Pure function for easy testing. Returns :ok or {:unsafe, message}.
  # If a prod release is running with :allow_dev_activate=true (a
  # config-merge mistake, an env-var override, a bad sys.config patch),
  # refuse to boot.
  @doc false
  def check_dev_activate_safe(compile_env, runtime_flag) do
    if compile_env == :prod and runtime_flag do
      {:unsafe,
       """
       REFUSING TO BOOT: :allow_dev_activate is true in a prod release.

       :pki_ca_engine, :allow_dev_activate is the escape hatch that bypasses
       the key-ceremony threshold and injects raw private keys. It is never
       safe to enable in production. The fact that it's set indicates a
       config-merge mistake that must be fixed before continuing.

       Set :allow_dev_activate to false (or remove it) in your prod config
       and restart.
       """}
    else
      :ok
    end
  end
end
