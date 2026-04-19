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

# ── esbuild (asset bundling) ─────────────────────────────────────────────────
config :esbuild,
  version: "0.25.4",
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

# ── tailwind (CSS compilation) ───────────────────────────────────────────────
config :tailwind,
  version: "4.1.12",
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
  http: [port: 4010]

# Dev-only secret_key_base (production MUST set SECRET_KEY_BASE env var)
if config_env() != :prod do
  config :pki_tenant_web, PkiTenantWeb.Endpoint,
    secret_key_base: "dev-only-secret-key-base-that-is-at-least-64-bytes-long-for-phoenix-endpoint-config"
end

# ── Tenant Web dev watchers ─────────────────────────────────────────────────
if config_env() == :dev do
  config :pki_tenant_web, PkiTenantWeb.Endpoint,
    watchers: [
      esbuild: {Esbuild, :install_and_run, [:pki_tenant_web, ~w(--sourcemap=inline --watch)]},
      tailwind: {Tailwind, :install_and_run, [:pki_tenant_web, ~w(--watch)]}
    ],
    live_reload: [
      patterns: [
        ~r"src/pki_tenant_web/lib/pki_tenant_web/(live|components)/.*(ex|heex)$"
      ]
    ]
end

# ── Logging ──────────────────────────────────────────────────────────────────
# JSON logging in production (LoggerJSON 6.x uses formatter API, not backends)
if config_env() == :prod do
  config :logger, :default_handler,
    formatter: {LoggerJSON.Formatters.Basic, metadata: :all}
end

# Per-env overrides. Only test.exs exists today — dev/prod use runtime.exs.
if File.exists?(Path.expand("#{config_env()}.exs", __DIR__)) do
  import_config "#{config_env()}.exs"
end
