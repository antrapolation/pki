import Config

# For development, we disable any cache and enable
# debugging and code reloading.
config :pki_platform_portal, PkiPlatformPortalWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4006],
  check_origin: false,
  code_reloader: true,
  debug_errors: true,
  secret_key_base: "rVZ3s99uzntf1L5NpyautO5qAXu8yFFRjmVKYOT39fQqF8Hql1sxO6uXFepW46YiyumSnqrbByLF3Ofooecusw==",
  watchers: [
    esbuild:
      {Esbuild, :install_and_run, [:pki_platform_portal, ~w(--sourcemap=inline --watch)]},
    tailwind: {Tailwind, :install_and_run, [:pki_platform_portal, ~w(--watch)]}
  ]

# Reload browser tabs when matching files change.
config :pki_platform_portal, PkiPlatformPortalWeb.Endpoint,
  live_reload: [
    web_console_logger: true,
    patterns: [
      ~r"priv/static/(?!uploads/).*\.(js|css|png|jpeg|jpg|gif|svg)$",
      ~r"priv/gettext/.*\.po$",
      ~r"lib/pki_platform_portal_web/router\.ex$",
      ~r"lib/pki_platform_portal_web/(controllers|live|components)/.*\.(ex|heex)$"
    ]
  ]

# Enable dev routes for dashboard and mailbox
config :pki_platform_portal, dev_routes: true

# Do not include metadata nor timestamps in development logs
config :logger, :default_formatter, format: "[$level] $message\n"

# Set a higher stacktrace during development. Avoid configuring such
# in production as building large stacktraces may be expensive.
config :phoenix, :stacktrace_depth, 20

# Initialize plugs at runtime for faster development compilation
config :phoenix, :plug_init_mode, :runtime

config :phoenix_live_view,
  debug_heex_annotations: true,
  debug_attributes: true,
  enable_expensive_runtime_checks: true

# Platform admin credentials (override in runtime.exs for production)
config :pki_platform_portal, admin_username: "admin"
config :pki_platform_portal, admin_password: "admin"

# PlatformRepo config for tenancy
config :pki_platform_engine, PkiPlatformEngine.PlatformRepo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: 5432,
  database: "pki_platform_dev",
  pool_size: 5

# TenantRepo config (base connection info for dynamic tenant DBs)
config :pki_platform_engine, PkiPlatformEngine.TenantRepo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: 5432,
  pool_size: 2

# Audit trail Repo (PkiAuditTrail still uses Postgres).
config :pki_audit_trail, PkiAuditTrail.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: 5432,
  database: "pki_ca_engine_dev",
  pool_size: 2

# Validation engine — auto-start HTTP on port 4005
config :pki_validation, PkiValidation.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: 5432,
  database: "pki_validation_dev",
  pool_size: 5

config :pki_validation, :http, start: true, port: 4005

# Hammer rate limiter config
config :hammer,
  backend: {Hammer.Backend.ETS, [expiry_ms: 60_000 * 60 * 2, cleanup_interval_ms: 60_000 * 10]}

# Relax rate limiting in dev to avoid being blocked during debugging
config :pki_platform_portal, :rate_limit_enabled, false

# Longer session timeout in dev to avoid being logged out during debugging
config :pki_platform_portal,
  session_idle_timeout_ms: 120 * 60 * 1000,
  session_ip_pinning: false
