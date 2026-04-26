import Config

config :phoenix, :json_library, Jason

# esbuild + tailwind profiles (needed when running standalone, not from root)
config :esbuild,
  version: "0.25.4",
  pki_tenant_web: [
    args:
      ~w(js/app.js --bundle --target=es2022 --outdir=../priv/static/assets/js --external:/fonts/* --external:/images/* --alias:@=.),
    cd: Path.expand("../assets", __DIR__),
    env: %{"NODE_PATH" => Path.expand("../../deps", __DIR__)}
  ]

config :tailwind,
  version: "4.1.12",
  pki_tenant_web: [
    args: ~w(
      --input=assets/css/app.css
      --output=priv/static/assets/css/app.css
    ),
    cd: Path.expand("..", __DIR__)
  ]

# Hammer rate limiter (ETS backend — in-memory, per-node)
config :hammer,
  backend:
    {Hammer.Backend.ETS, [expiry_ms: 60_000 * 60 * 2, cleanup_interval_ms: 60_000 * 10]}

# Inject PubSub module into pki_ca_engine so AgentHandler can broadcast
# agent-connected events to HsmDevicesLive without creating a hard dep on Phoenix.
config :pki_ca_engine, pubsub_module: PkiTenantWeb.PubSub

config :pki_tenant_web, PkiTenantWeb.Endpoint,
  url: [host: "localhost"],
  adapter: Bandit.PhoenixAdapter,
  render_errors: [formats: [html: PkiTenantWeb.ErrorHTML], layout: false],
  pubsub_server: PkiTenantWeb.PubSub,
  live_view: [signing_salt: "TnNtW3bQ"],
  secret_key_base: "dev-only-secret-key-base-that-is-at-least-64-bytes-long-for-phoenix-endpoint-config",
  http: [port: 4010]

import_config "#{config_env()}.exs"
