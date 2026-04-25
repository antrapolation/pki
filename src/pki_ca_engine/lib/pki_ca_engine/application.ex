defmodule PkiCaEngine.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    assert_dev_activate_safe!()
    assert_no_software_keystore_in_prod!()
    assert_ceremony_signing_secret_set!()

    children =
      if Application.get_env(:pki_ca_engine, :start_application, true) do
        [
          {PkiCaEngine.CeremonyRegistry, name: :ceremony_pid_registry},
          {PkiCaEngine.KeyActivation,
           name: PkiCaEngine.KeyActivation,
           timeout_ms: Application.get_env(:pki_ca_engine, :key_activation_timeout_ms, 3_600_000)},
          {DynamicSupervisor, strategy: :one_for_one, name: PkiCaEngine.EngineSupervisor}
        ]
      else
        []
      end

    if Application.get_env(:pki_ca_engine, :start_application, true) do
      opts = [strategy: :rest_for_one, name: PkiCaEngine.Supervisor]
      Supervisor.start_link(children, opts)
    else
      Supervisor.start_link([], strategy: :one_for_one)
    end
  end

  @doc false
  def assert_ceremony_signing_secret_set! do
    if Application.get_env(:pki_ca_engine, :env) == :prod do
      case Application.get_env(:pki_ca_engine, :ceremony_signing_secret) do
        nil ->
          raise """
          REFUSING TO BOOT: :ceremony_signing_secret is not configured.
          Set config :pki_ca_engine, :ceremony_signing_secret, <32+ byte secret>
          in your runtime config. Using the default makes share HMAC signatures trivially forgeable.
          """

        "dev-only-secret" ->
          raise """
          REFUSING TO BOOT: :ceremony_signing_secret is set to the dev default.
          Replace it with a strong random secret in your runtime config.
          """

        _ ->
          :ok
      end
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

  @doc false
  def assert_no_software_keystore_in_prod! do
    env = Application.get_env(:pki_ca_engine, :env) ||
            Application.get_env(:pki_system, :env, :prod)

    allow_flag = Application.get_env(:pki_ca_engine, :allow_software_keystore_in_prod, false)

    if env == :prod and not allow_flag do
      alias PkiMnesia.{Repo, Structs.IssuerKey}

      case Repo.where(IssuerKey, fn k -> k.status == "active" and k.keystore_type == :software end) do
        {:ok, [_ | _] = keys} ->
          aliases = Enum.map_join(keys, ", ", fn k -> k.key_alias || k.id end)

          raise """
          REFUSING TO BOOT: active software-keystore IssuerKey(s) found in a prod release.

          The following IssuerKey(s) have keystore_type=:software and status=active:
            #{aliases}

          Software keystores store unprotected private key material in Mnesia. This is
          never acceptable in production. Migrate each key to an HSM-backed keystore
          and retry, or set:

            config :pki_ca_engine, :allow_software_keystore_in_prod, true

          in your prod config only if you intentionally accept this risk.
          """

        _ ->
          :ok
      end
    else
      :ok
    end
  end
end
