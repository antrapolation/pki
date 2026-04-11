import Config

config :pki_platform_engine, ecto_repos: [PkiPlatformEngine.PlatformRepo]

# Engine bootstrap implementations — called during tenant onboarding
# and dev key activation. Each module implements EngineBootstrap behaviour.
config :pki_platform_engine, :engine_bootstraps, [
  PkiCaEngine.EngineBootstrapImpl,
  PkiRaEngine.EngineBootstrapImpl
]

import_config "#{config_env()}.exs"
