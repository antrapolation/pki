import Config

config :pki_audit_trail, PkiAuditTrail.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  database: "pki_audit_trail_dev",
  stacktrace: true,
  show_sensitive_data_on_connection_error: true,
  pool_size: 10
