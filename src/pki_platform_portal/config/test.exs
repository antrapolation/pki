import Config

# We don't run a server during test. If one is required,
# you can enable the server option below.
config :pki_platform_portal, PkiPlatformPortalWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4012],
  secret_key_base: "Hm3nR8xKqT2pL7vJ3dF9bH4yA6cE1gI0sU8oN2kP5mX7zQ3wV6jD4rB9tY1uC0a",
  server: false

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
