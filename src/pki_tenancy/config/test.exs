import Config

config :pki_tenancy, PkiTenancy.PlatformRepo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: 5434,
  database: "pki_platform_test",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 10

config :logger, level: :warning
