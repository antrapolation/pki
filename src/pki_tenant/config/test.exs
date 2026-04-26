import Config

# Disable auto-start of the application during tests.
# Tests manage their own Mnesia lifecycle.
config :pki_tenant, start_application: false

# Satisfy ceremony_signing_secret boot guard in test — not used for real signing
config :pki_ca_engine, :ceremony_signing_secret, "test-only-not-for-production"
