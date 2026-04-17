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
  live_view: [signing_salt: "Xk9pR2wM"],
  cache_static_manifest: "priv/static/cache_manifest.json"

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
  live_view: [signing_salt: "a/Jpy5T4"],
  cache_static_manifest: "priv/static/cache_manifest.json"

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
  live_view: [signing_salt: "FeWYPwyL"],
  cache_static_manifest: "priv/static/cache_manifest.json"

# ── esbuild (asset bundling for all 3 portals) ─────────────────────────────
config :esbuild,
  version: "0.25.4",
  pki_ca_portal: [
    args:
      ~w(js/app.js --bundle --target=es2022 --outdir=../priv/static/assets/js --external:/fonts/* --external:/images/* --alias:@=.),
    cd: Path.expand("../src/pki_ca_portal/assets", __DIR__),
    env: %{"NODE_PATH" => [Path.expand("../deps", __DIR__), Mix.Project.build_path()]}
  ],
  pki_ra_portal: [
    args:
      ~w(js/app.js --bundle --target=es2022 --outdir=../priv/static/assets/js --external:/fonts/* --external:/images/* --alias:@=.),
    cd: Path.expand("../src/pki_ra_portal/assets", __DIR__),
    env: %{"NODE_PATH" => [Path.expand("../deps", __DIR__), Mix.Project.build_path()]}
  ],
  pki_platform_portal: [
    args:
      ~w(js/app.js --bundle --target=es2022 --outdir=../priv/static/assets/js --external:/fonts/* --external:/images/* --alias:@=.),
    cd: Path.expand("../src/pki_platform_portal/assets", __DIR__),
    env: %{"NODE_PATH" => [Path.expand("../deps", __DIR__), Mix.Project.build_path()]}
  ],
  pki_tenant_web: [
    args:
      ~w(js/app.js --bundle --target=es2022 --outdir=../priv/static/assets/js --external:/fonts/* --external:/images/* --alias:@=.),
    cd: Path.expand("../src/pki_tenant_web/assets", __DIR__),
    env: %{"NODE_PATH" => [Path.expand("../deps", __DIR__), Mix.Project.build_path()]}
  ]

# ── tailwind (CSS compilation for all 3 portals) ───────────────────────────
config :tailwind,
  version: "4.1.12",
  pki_ca_portal: [
    args: ~w(
      --input=assets/css/app.css
      --output=priv/static/assets/css/app.css
    ),
    cd: Path.expand("../src/pki_ca_portal", __DIR__)
  ],
  pki_ra_portal: [
    args: ~w(
      --input=assets/css/app.css
      --output=priv/static/assets/css/app.css
    ),
    cd: Path.expand("../src/pki_ra_portal", __DIR__)
  ],
  pki_platform_portal: [
    args: ~w(
      --input=assets/css/app.css
      --output=priv/static/assets/css/app.css
    ),
    cd: Path.expand("../src/pki_platform_portal", __DIR__)
  ],
  pki_tenant_web: [
    args: ~w(
      --input=assets/css/app.css
      --output=priv/static/assets/css/app.css
    ),
    cd: Path.expand("../src/pki_tenant_web", __DIR__)
  ]

# ── Tenant Web endpoint ──────────────────────────────────────────────────────
config :pki_tenant_web, PkiTenantWeb.Endpoint,
  url: [host: "localhost"],
  adapter: Bandit.PhoenixAdapter,
  render_errors: [formats: [html: PkiTenantWeb.ErrorHTML], layout: false],
  pubsub_server: PkiTenantWeb.PubSub,
  live_view: [signing_salt: "TnNtW3bQ"],
  secret_key_base: "dev-only-secret-key-base-that-is-at-least-64-bytes-long-for-phoenix-endpoint-config",
  http: [port: 4010]

# ── Logging ──────────────────────────────────────────────────────────────────
# JSON logging in production (LoggerJSON 6.x uses formatter API, not backends)
if config_env() == :prod do
  config :logger, :default_handler,
    formatter: {LoggerJSON.Formatters.Basic, metadata: :all}
end
