import Config

config :pki_tenancy, PkiTenancy.PlatformRepo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: 5434,
  database: "pki_platform_dev",
  pool_size: 10

config :pki_tenancy, PkiTenancy.TenantRepo,
  hostname: "localhost",
  port: 5434,
  username: "postgres",
  password: "postgres",
  pool_size: 2
