import Config

config :pki_ra_engine, PkiRaEngine.Repo,
  database: "pki_ra_engine_dev",
  stacktrace: true,
  show_sensitive_data_on_connection_error: true,
  pool_size: 10

config :pki_ra_engine, start_http: true
