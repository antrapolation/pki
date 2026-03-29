import Config

config :pki_ca_engine, ecto_repos: [PkiCaEngine.Repo]

config :hammer,
  backend: {Hammer.Backend.ETS, [expiry_ms: 60_000 * 60 * 2, cleanup_interval_ms: 60_000 * 10]}

import_config "#{config_env()}.exs"
