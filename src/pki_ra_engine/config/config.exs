import Config

config :pki_ra_engine,
  ecto_repos: [PkiRaEngine.Repo]

config :pki_ra_engine, PkiRaEngine.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: 5432

import_config "#{config_env()}.exs"
