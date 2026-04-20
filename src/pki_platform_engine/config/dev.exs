import Config

config :pki_platform_engine, PkiPlatformEngine.PlatformRepo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: 5432,
  database: "pki_platform_dev",
  pool_size: 3

config :pki_platform_engine, PkiPlatformEngine.TenantRepo,
  hostname: "localhost",
  port: 5432,
  username: "postgres",
  password: "postgres",
  pool_size: 2

# Dev-only: put spawned tenants' Mnesia directories under the repo so no
# root permissions are needed. Prod uses /var/lib/pki/tenants (default).
config :pki_platform_engine,
  tenant_mnesia_base: Path.expand("../../../_dev_tenants", __DIR__)
