import Config

config :pki_ca_engine, PkiCaEngine.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  database: "pki_ca_engine_dev",
  stacktrace: true,
  show_sensitive_data_on_connection_error: true,
  pool_size: 10

# HTTP API server
config :pki_ca_engine, :start_http, true
config :pki_ca_engine, :http_port, 4001
config :pki_ca_engine, :internal_api_secret, "dev-secret"
config :pki_ca_engine, :validation_url, "http://localhost:4005"
