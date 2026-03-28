import Config

config :pki_platform_engine, ecto_repos: [PkiPlatformEngine.PlatformRepo]

import_config "#{config_env()}.exs"
