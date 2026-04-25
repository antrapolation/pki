import Config

# Don't start the endpoint during tests
config :pki_tenant_web, PkiTenantWeb.Endpoint, server: false

# Disable pki_tenant app auto-start in tests (Mnesia needs explicit setup)
config :pki_tenant, start_application: false

# Satisfy ceremony_signing_secret boot guard in test — not used for real signing
config :pki_ca_engine, :ceremony_signing_secret, "test-only-not-for-production"
