import Config

# Compile-time configuration shared across all releases.
# Runtime configuration is in config/runtime.exs.
#
# IMPORTANT: In umbrella releases, child app config/*.exs files are NOT loaded.
# All compile-time config must live here (or in dev.exs / prod.exs / runtime.exs).

config :pki_system, env: config_env()

# ── JSON library ─────────────────────────────────────────────────────────────
config :phoenix, :json_library, Jason

# ── Hammer rate limiter (ETS backend — in-memory, per-node) ──────────────────
config :hammer,
  backend: {Hammer.Backend.ETS, [expiry_ms: 60_000 * 60 * 2, cleanup_interval_ms: 60_000 * 10]}

# ── Platform Portal endpoint ─────────────────────────────────────────────────
config :pki_platform_portal,
  generators: [timestamp_type: :utc_datetime],
  trusted_proxies: ["127.0.0.1", "::1"],
  session_idle_timeout_ms: 30 * 60 * 1000

config :pki_platform_portal, PkiPlatformPortalWeb.Endpoint,
  url: [host: "localhost"],
  adapter: Bandit.PhoenixAdapter,
  render_errors: [
    formats: [html: PkiPlatformPortalWeb.ErrorHTML, json: PkiPlatformPortalWeb.ErrorJSON],
    layout: false
  ],
  pubsub_server: PkiPlatformPortal.PubSub,
  live_view: [signing_salt: "Xk9pR2wM"]

# ── CA Portal endpoint ───────────────────────────────────────────────────────
config :pki_ca_portal,
  generators: [timestamp_type: :utc_datetime],
  trusted_proxies: ["127.0.0.1", "::1"],
  session_idle_timeout_ms: 30 * 60 * 1000

config :pki_ca_portal, PkiCaPortalWeb.Endpoint,
  url: [host: "localhost"],
  adapter: Bandit.PhoenixAdapter,
  render_errors: [
    formats: [html: PkiCaPortalWeb.ErrorHTML, json: PkiCaPortalWeb.ErrorJSON],
    layout: false
  ],
  pubsub_server: PkiCaPortal.PubSub,
  live_view: [signing_salt: "a/Jpy5T4"]

# ── RA Portal endpoint ───────────────────────────────────────────────────────
config :pki_ra_portal,
  generators: [timestamp_type: :utc_datetime],
  trusted_proxies: ["127.0.0.1", "::1"],
  session_idle_timeout_ms: 30 * 60 * 1000

config :pki_ra_portal, PkiRaPortalWeb.Endpoint,
  url: [host: "localhost"],
  adapter: Bandit.PhoenixAdapter,
  render_errors: [
    formats: [html: PkiRaPortalWeb.ErrorHTML, json: PkiRaPortalWeb.ErrorJSON],
    layout: false
  ],
  pubsub_server: PkiRaPortal.PubSub,
  live_view: [signing_salt: "FeWYPwyL"]

# ── Logging ──────────────────────────────────────────────────────────────────
# JSON logging in production (LoggerJSON 6.x uses formatter API, not backends)
if config_env() == :prod do
  config :logger, :default_handler,
    formatter: {LoggerJSON.Formatters.Basic, metadata: :all}
end
