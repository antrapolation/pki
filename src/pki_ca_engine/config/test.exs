import Config

config :pki_ca_engine, :validation_url, nil
config :pki_ca_engine, :internal_api_secret, "test-secret"

# Audit trail Repo config (shares a test DB used by pki_audit_trail itself).
config :pki_audit_trail, PkiAuditTrail.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: 5432,
  database: "pki_ca_engine_test",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 5

config :logger, level: :warning
