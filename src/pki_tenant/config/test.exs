import Config

# Disable auto-start of the application during tests.
# Tests manage their own Mnesia lifecycle.
config :pki_tenant, start_application: false
