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

# pki_ca_engine's own config.exs sets `:pki_ca_engine, :env, config_env()`,
# but path-dep configs don't merge when the dep is pulled from a sibling
# project. Without this line, `PkiCaEngine.Application.assert_dev_activate_safe!`
# defaults `compile_env` to `:prod` (fail-closed), sees
# `:allow_dev_activate == true` above, and refuses to boot.
config :pki_ca_engine, :env, config_env()

config :logger, level: :warning
