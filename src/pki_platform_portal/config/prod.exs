import Config

config :pki_platform_portal, PkiPlatformPortalWeb.Endpoint,
  cache_static_manifest: "priv/static/cache_manifest.json"

config :pki_platform_portal, PkiPlatformPortalWeb.Endpoint,
  force_ssl: [
    rewrite_on: [:x_forwarded_proto],
    exclude: [
      hosts: ["localhost", "127.0.0.1"]
    ]
  ]

# Signing salt is configured in runtime.exs to avoid compile_env mismatches
# when running via mix (not releases).

# Structured JSON logging for production — enables log aggregation
config :logger, :default_handler,
  formatter: {LoggerJSON.Formatters.Basic, metadata: :all}

config :logger, level: :info
