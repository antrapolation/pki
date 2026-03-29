import Config

config :pki_ra_engine,
  ecto_repos: [PkiRaEngine.Repo]

config :hammer,
  backend: {Hammer.Backend.ETS, [expiry_ms: 60_000 * 60 * 2, cleanup_interval_ms: 60_000 * 10]}

import_config "#{config_env()}.exs"
