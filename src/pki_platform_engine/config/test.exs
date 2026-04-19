import Config

config :pki_platform_engine, PkiPlatformEngine.PlatformRepo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: 5432,
  database: "pki_platform_test",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 10

config :pki_platform_engine, PkiPlatformEngine.TenantRepo,
  hostname: "localhost",
  port: 5432,
  direct_port: 5432,
  username: "postgres",
  password: "postgres",
  pool_size: 5

# Disable date log handler in test
config :pki_platform_engine, :start_date_log_handler, false

config :logger, level: :warning
