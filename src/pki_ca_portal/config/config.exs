# This file is responsible for configuring your application
# and its dependencies with the aid of the Config module.
#
# This configuration file is loaded before any dependency and
# is restricted to this project.

# General application configuration
import Config

config :pki_ca_portal,
  generators: [timestamp_type: :utc_datetime],
  # IPs of trusted reverse proxies — only these may set X-Forwarded-For
  trusted_proxies: ["127.0.0.1", "::1"]

# Configure the endpoint
config :pki_ca_portal, PkiCaPortalWeb.Endpoint,
  url: [host: "localhost"],
  adapter: Bandit.PhoenixAdapter,
  render_errors: [
    formats: [html: PkiCaPortalWeb.ErrorHTML, json: PkiCaPortalWeb.ErrorJSON],
    layout: false
  ],
  pubsub_server: PkiCaPortal.PubSub,
  live_view: [signing_salt: "a/Jpy5T4"]

# Configure esbuild (the version is required)
config :esbuild,
  version: "0.25.4",
  pki_ca_portal: [
    args:
      ~w(js/app.js --bundle --target=es2022 --outdir=../priv/static/assets/js --external:/fonts/* --external:/images/* --alias:@=.),
    cd: Path.expand("../assets", __DIR__),
    env: %{"NODE_PATH" => [Path.expand("../deps", __DIR__), Mix.Project.build_path()]}
  ]

# Configure tailwind (the version is required)
config :tailwind,
  version: "4.1.12",
  pki_ca_portal: [
    args: ~w(
      --input=assets/css/app.css
      --output=priv/static/assets/css/app.css
    ),
    cd: Path.expand("..", __DIR__)
  ]

# Configure Elixir's Logger
config :logger, :default_formatter,
  format: "$time $metadata[$level] $message\n",
  metadata: [:request_id]

# Use Jason for JSON parsing in Phoenix
config :phoenix, :json_library, Jason

# Hammer rate limiter (ETS backend — in-memory, per-node)
config :hammer,
  backend: {Hammer.Backend.ETS, [expiry_ms: 60_000 * 60 * 2, cleanup_interval_ms: 60_000 * 10]}

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
import_config "#{config_env()}.exs"
