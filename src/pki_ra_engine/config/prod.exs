import Config

config :pki_ra_engine, PkiRaEngine.Repo,
  database: "pki_ra_engine_prod",
  pool_size: 10

config :pki_ra_engine, start_http: true
