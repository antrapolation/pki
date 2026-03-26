import Config

# For development, we disable any cache and enable
# debugging and code reloading.
config :pki_platform_portal, PkiPlatformPortalWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4006],
  check_origin: false,
  code_reloader: true,
  debug_errors: true,
  secret_key_base: "Wm8nT5xKqR2pL7vJ3dF9bH4yA6cE1gI0sU8oN2kP5mX7zQ3wV6jD4rB9tY1uC0a",
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
