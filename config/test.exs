import Config

# Test environment: disable auto-start of applications whose supervision trees
# conflict when co-located in a single BEAM node. In tenant mode, pki_tenant
# owns the CA/RA/validation/audit supervisors; the legacy engine apps must
# not also boot their named singletons.
#
# Each legacy app's Application.start checks this flag and boots an empty
# supervisor when false. Tests bring up only the subsystems they need.

config :pki_tenant, start_application: false
config :pki_tenant_web, PkiTenantWeb.Endpoint, server: false

config :pki_ca_engine, start_application: false
config :pki_ra_engine, start_application: false
config :pki_validation, start_application: false
config :pki_audit_trail, start_application: false
config :pki_platform_engine, start_application: false

# libcluster: use no-op topology in tests (no multi-node discovery).
config :libcluster, topologies: []
