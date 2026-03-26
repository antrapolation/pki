import Config

config :pki_tenancy, ecto_repos: [PkiTenancy.PlatformRepo]

import_config "#{config_env()}.exs"
