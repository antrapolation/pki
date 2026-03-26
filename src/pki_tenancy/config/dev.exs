import Config

config :pki_tenancy, PkiTenancy.PlatformRepo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: 5434,
  database: "pki_platform_dev",
  pool_size: 10
