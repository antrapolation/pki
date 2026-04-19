import Config

# Don't start the endpoint during tests
config :pki_tenant_web, PkiTenantWeb.Endpoint, server: false

# Disable pki_tenant app auto-start in tests (Mnesia needs explicit setup)
config :pki_tenant, start_application: false
