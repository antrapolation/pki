import Config

# We don't run a server during test. If one is required,
# you can enable the server option below.
config :pki_platform_portal, PkiPlatformPortalWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4012],
  secret_key_base: "Hm3nR8xKqT2pL7vJ3dF9bH4yA6cE1gI0sU8oN2kP5mX7zQ3wV6jD4rB9tY1uC0aWm8nT5xKqR2pL7vJ3dF9bH4yA6cE1gI0sU8oN2kP5mX7z",
  server: false

# Disable date log handler in test
config :pki_platform_portal, :start_date_log_handler, false

# Print only warnings and errors during test
config :logger, level: :warning

# Initialize plugs at runtime for faster test compilation
config :phoenix, :plug_init_mode, :runtime

# Enable helpful, but potentially expensive runtime checks
config :phoenix_live_view,
  enable_expensive_runtime_checks: true

# Sort query params output of verified routes for robust url comparisons
config :phoenix,
  sort_verified_routes_query_params: true

# Platform admin credentials for tests
config :pki_platform_portal, admin_username: "admin"
config :pki_platform_portal, admin_password: "admin"

# PlatformRepo config for tenancy (used by dashboard/tenants)
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

config :pki_ca_engine, PkiCaEngine.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: 5434,
  database: "pki_ca_engine_test",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 2

config :pki_audit_trail, PkiAuditTrail.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: 5434,
  database: "pki_ca_engine_test",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 2

config :pki_ra_engine, PkiRaEngine.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: 5434,
  database: "pki_ra_engine_test",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 2
