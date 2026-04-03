import Config

# We don't run a server during test. If one is required,
# you can enable the server option below.
config :pki_ca_portal, PkiCaPortalWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4002],
  secret_key_base: "9m3Lx1MQa/shM2Ll7NeVaM8L4C3fqJWIOInRdRsFZkR+ZdR04wY40f/F12EYBI57",
  server: false

# Use mock CA engine client in tests
config :pki_ca_portal, :ca_engine_client, PkiCaPortal.CaEngineClient.Mock

# DB configs for engine dependencies (needed for app startup in test)
config :pki_ca_engine, PkiCaEngine.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: 5434,
  database: "pki_ca_engine_test",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 5

config :pki_audit_trail, PkiAuditTrail.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: 5434,
  database: "pki_ca_engine_test",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 2

config :pki_platform_engine, PkiPlatformEngine.PlatformRepo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: 5434,
  database: "pki_platform_test",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 3

config :pki_platform_engine, PkiPlatformEngine.TenantRepo,
  hostname: "localhost",
  port: 5434,
  username: "postgres",
  password: "postgres",
  pool_size: 2

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
