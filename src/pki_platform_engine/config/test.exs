import Config

config :pki_platform_engine, PkiPlatformEngine.PlatformRepo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: 5434,
  database: "pki_platform_test",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 10

config :pki_platform_engine, PkiPlatformEngine.TenantRepo,
  hostname: "localhost",
  port: 5434,
  username: "postgres",
  password: "postgres",
  pool_size: 2

config :logger, level: :warning
