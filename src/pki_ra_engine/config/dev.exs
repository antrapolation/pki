import Config

config :pki_ra_engine, PkiRaEngine.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: 5432,
  database: "pki_ra_engine_dev",
  stacktrace: true,
  show_sensitive_data_on_connection_error: true,
  pool_size: 10

config :pki_ra_engine, start_http: true

# CA Engine connection defaults for local development.
# Uses DefaultCaClient (stub) unless you explicitly set HttpCaClient below.
config :pki_ra_engine,
  ca_engine_url: "http://localhost:4001",
  internal_api_secret: "dev-secret",
  ca_engine_module: PkiRaEngine.CsrValidation.DefaultCaClient
