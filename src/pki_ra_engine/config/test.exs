import Config

# Transitive repos that boot under `mix test` need `:database`
# set or Postgrex crashes with "missing the :database key".
# Matches the fix in pki_validation + pki_ca_engine — all of
# these pull pki_platform_engine as a path dep but path-dep
# configs don't merge.
config :pki_platform_engine, PkiPlatformEngine.PlatformRepo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: 5432,
  database: "pki_ra_engine_test",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 2

config :pki_audit_trail, PkiAuditTrail.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: 5432,
  database: "pki_ra_engine_test",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 2

# Same compile-env pin as pki_validation/pki_ca_engine — stops
# PkiCaEngine.Application.assert_dev_activate_safe! from falling
# back to :prod default when its own config/config.exs isn't
# merged into this sibling's test env.
config :pki_ca_engine, :env, config_env()

config :logger, level: :warning

config :pki_ra_engine, start_dcv_poller: false
config :pki_ra_engine, ca_engine_module: PkiRaEngine.CsrValidation.DefaultCaClient
