import Config

config :pki_ca_engine, PkiCaEngine.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  database: "pki_ca_engine_dev",
  stacktrace: true,
  show_sensitive_data_on_connection_error: true,
  pool_size: 10
