import Config

config :pki_ra_engine,
  ecto_repos: [PkiRaEngine.Repo]

import_config "#{config_env()}.exs"
