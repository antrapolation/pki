import Config

config :pki_ca_engine, ecto_repos: [PkiCaEngine.Repo]

import_config "#{config_env()}.exs"
