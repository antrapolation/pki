import Config

config :pki_audit_trail, PkiAuditTrail.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  database: "pki_audit_trail_test",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 10

config :logger, level: :warning
