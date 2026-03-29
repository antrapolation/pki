import Config

config :pki_audit_trail, PkiAuditTrail.Repo,
  username: "postgres",
  password: System.get_env("POSTGRES_PASSWORD", "postgres"),
  hostname: "localhost",
  port: String.to_integer(System.get_env("POSTGRES_PORT", "5432")),
  database: System.get_env("CA_ENGINE_DB", "pki_audit_trail_dev"),
  stacktrace: true,
  show_sensitive_data_on_connection_error: true,
  pool_size: 10
