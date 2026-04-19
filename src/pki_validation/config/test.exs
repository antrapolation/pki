import Config

config :pki_validation, :http, start: false
config :pki_validation, :internal_api_secret, "test-secret"

# pki_ca_engine is a dep — it brings in Ecto repos that need a DB config or
# they crash on startup. Provide dummy configs (connections will fail but
# the pool starts). Our tests only exercise Mnesia-backed code paths.
config :pki_ca_engine, PkiCaEngine.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: 5432,
  database: "pki_validation_test",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 1

config :pki_audit_trail, PkiAuditTrail.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: 5432,
  database: "pki_validation_test",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 1

config :pki_platform_engine, PkiPlatformEngine.PlatformRepo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: 5432,
  database: "pki_validation_test",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 1

# Hammer rate-limiter — required expiry_ms config
config :hammer,
  backend: {Hammer.Backend.ETS, [expiry_ms: 60_000 * 60 * 4, cleanup_interval_ms: 60_000 * 10]}

config :pki_ca_engine, :allow_dev_activate, true

config :logger, level: :warning
