import Config

config :pki_ca_engine, PkiCaEngine.Repo,
  username: "postgres",
  password: System.get_env("POSTGRES_PASSWORD", "postgres"),
  hostname: "localhost",
  port: String.to_integer(System.get_env("POSTGRES_PORT", "5432")),
  database: System.get_env("CA_ENGINE_DB", "pki_ca_engine_dev"),
  stacktrace: true,
  show_sensitive_data_on_connection_error: true,
  pool_size: 10

config :pki_audit_trail, PkiAuditTrail.Repo,
  username: "postgres",
  password: System.get_env("POSTGRES_PASSWORD", "postgres"),
  hostname: "localhost",
  port: String.to_integer(System.get_env("POSTGRES_PORT", "5432")),
  database: System.get_env("AUDIT_TRAIL_DB", "pki_ca_engine_dev"),
  pool_size: 2

# HTTP API server
config :pki_ca_engine, :start_http, true
config :pki_ca_engine, :http_port, String.to_integer(System.get_env("PORT", "4001"))
config :pki_ca_engine, :internal_api_secret, System.get_env("INTERNAL_API_SECRET", "dev-secret")
config :pki_ca_engine, :validation_url, System.get_env("VALIDATION_URL", "http://localhost:4005")
