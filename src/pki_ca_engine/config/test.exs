import Config

config :pki_ca_engine, PkiCaEngine.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: 5434,
  database: "pki_ca_engine_test",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 10

config :pki_ca_engine, :validation_url, nil

# Audit trail Repo config (shares the same test database)
config :pki_audit_trail, PkiAuditTrail.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: 5434,
  database: "pki_ca_engine_test",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 5
config :pki_ca_engine, :internal_api_secret, "test-secret"

config :logger, level: :warning
