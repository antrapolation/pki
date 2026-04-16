import Config

config :phoenix, :json_library, Jason

# Hammer rate limiter (ETS backend — in-memory, per-node)
config :hammer,
  backend:
    {Hammer.Backend.ETS, [expiry_ms: 60_000 * 60 * 2, cleanup_interval_ms: 60_000 * 10]}

config :pki_tenant_web, PkiTenantWeb.Endpoint,
  url: [host: "localhost"],
  adapter: Bandit.PhoenixAdapter,
  render_errors: [formats: [html: PkiTenantWeb.ErrorHTML], layout: false],
  pubsub_server: PkiTenantWeb.PubSub,
  live_view: [signing_salt: "TnNtW3bQ"],
  secret_key_base: "dev-only-secret-key-base-that-is-at-least-64-bytes-long-for-phoenix-endpoint-config",
  http: [port: 4010]

# Disable pki_tenant app auto-start in tests
config :pki_tenant, start_application: false

import_config "#{config_env()}.exs"
