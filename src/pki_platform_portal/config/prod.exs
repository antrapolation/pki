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

# Signing salt — read at BUILD time (compile_env in endpoint.ex).
# Set PLATFORM_SIGNING_SALT in the build environment or source .env before mix release.
if salt = System.get_env("PLATFORM_SIGNING_SALT") do
  config :pki_platform_portal, signing_salt: salt
end

config :logger, level: :info

config :logger, :console,
  format: "[$level] $time request_id=$metadata{request_id} remote_ip=$metadata{remote_ip} $message\n",
  metadata: [:request_id, :remote_ip, :module, :function]
