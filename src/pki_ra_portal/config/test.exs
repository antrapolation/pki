import Config

# We don't run a server during test. If one is required,
# you can enable the server option below.
config :pki_ra_portal, PkiRaPortalWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4002],
  secret_key_base: "hElcNajnPl4ePfI2F3WlpEOoLSnpcX5KPEzF1b3JQV8jscllf9WlCJZ6zPaGcy4r",
  server: false

# Use mock RA engine client in tests
config :pki_ra_portal, :ra_engine_client, PkiRaPortal.RaEngineClient.Mock

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
