import Config

# Audit trail Repo config (shares a test DB used by pki_audit_trail itself).
config :pki_audit_trail, PkiAuditTrail.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: 5432,
  database: "pki_ca_engine_test",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 5

# pki_platform_engine is a transitive dep — its PlatformRepo boots
# during `mix test`, so it needs a `database:` key or Postgrex
# crashes on start with `ArgumentError: missing the :database key`.
# Uses the pki_ca_engine_test DB since we don't exercise
# platform-level tables in this suite.
config :pki_platform_engine, PkiPlatformEngine.PlatformRepo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: 5432,
  database: "pki_ca_engine_test",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 2

# Pin compile_env so PkiCaEngine.Application.assert_dev_activate_safe!
# doesn't refuse to boot under :prod default when :allow_dev_activate
# is flipped true for tests that need it.
config :pki_ca_engine, :env, config_env()

config :logger, level: :warning
