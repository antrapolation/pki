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

config :logger, level: :info
