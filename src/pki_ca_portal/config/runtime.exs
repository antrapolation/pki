import Config

# config/runtime.exs is executed for all environments, including
# during releases. It is executed after compilation and before the
# system starts, so it is typically used to load production configuration
# and secrets from environment variables or elsewhere. Do not define
# any compile-time configuration in here, as it won't be applied.
# The block below contains prod specific runtime configuration.

# ## Using releases
#
# If you use `mix release`, you need to explicitly enable the server
# by passing the PHX_SERVER=true when you start it:
#
#     PHX_SERVER=true bin/pki_ca_portal start
#
# Alternatively, you can use `mix phx.gen.release` to generate a `bin/server`
# script that automatically sets the env var above.
if System.get_env("PHX_SERVER") do
  config :pki_ca_portal, PkiCaPortalWeb.Endpoint, server: true
end

config :pki_ca_portal, PkiCaPortalWeb.Endpoint,
  http: [port: String.to_integer(System.get_env("CA_PORTAL_PORT", System.get_env("PORT", "4002")))]

# PlatformRepo config — pki_platform_engine is a dependency and needs its DB configured
if platform_db_url = System.get_env("PLATFORM_DATABASE_URL") || System.get_env("DATABASE_URL") do
  config :pki_platform_engine, PkiPlatformEngine.PlatformRepo,
    url: platform_db_url,
    pool_size: String.to_integer(System.get_env("POOL_SIZE", "5"))
end

if cookie_secure = System.get_env("COOKIE_SECURE") do
  config :pki_ca_portal, cookie_secure: cookie_secure == "true"
end

if config_env() == :prod do
  # CA Engine configuration (URL not required in direct mode)
  ca_engine_url = System.get_env("CA_ENGINE_URL") || "http://localhost:4001"

  internal_api_secret =
    System.get_env("INTERNAL_API_SECRET") ||
      raise """
      environment variable INTERNAL_API_SECRET is missing.
      This secret is used to authenticate API calls to the CA Engine.
      """

  client_module =
    case System.get_env("ENGINE_CLIENT_MODE") do
      "mock" ->
        require Logger
        Logger.warning("ENGINE_CLIENT_MODE=mock is active. Using mock engine client. NOT FOR PRODUCTION.")
        PkiCaPortal.CaEngineClient.Mock

      "direct" ->
        # Single-node BEAM: portal calls engine modules in-process (no HTTP)
        PkiCaPortal.CaEngineClient.Direct

      _ ->
        PkiCaPortal.CaEngineClient.Http
    end

  config :pki_ca_portal,
    ca_engine_client: client_module,
    ca_engine_url: ca_engine_url,
    internal_api_secret: internal_api_secret

  # The secret key base is used to sign/encrypt cookies and other secrets.
  # A default value is used in config/dev.exs and config/test.exs but you
  # want to use a different value for prod and you most likely don't want
  # to check this value into version control, so we use an environment
  # variable instead.
  secret_key_base =
    System.get_env("SECRET_KEY_BASE") ||
      raise """
      environment variable SECRET_KEY_BASE is missing.
      You can generate one by calling: mix phx.gen.secret
      """

  host = System.get_env("CA_PORTAL_HOST") || System.get_env("PHX_HOST") || "example.com"

  config :pki_ca_portal, :dns_cluster_query, System.get_env("DNS_CLUSTER_QUERY")

  config :pki_ca_portal, PkiCaPortalWeb.Endpoint,
    url: [host: host, port: 443, scheme: "https"],
    http: [
      # Enable IPv6 and bind on all interfaces.
      # Set it to  {0, 0, 0, 0, 0, 0, 0, 1} for local network only access.
      # See the documentation on https://hexdocs.pm/bandit/Bandit.html#t:options/0
      # for details about using IPv6 vs IPv4 and loopback vs public addresses.
      ip: {0, 0, 0, 0, 0, 0, 0, 0}
    ],
    secret_key_base: secret_key_base

  # ## SSL Support
  #
  # To get SSL working, you will need to add the `https` key
  # to your endpoint configuration:
  #
  #     config :pki_ca_portal, PkiCaPortalWeb.Endpoint,
  #       https: [
  #         ...,
  #         port: 443,
  #         cipher_suite: :strong,
  #         keyfile: System.get_env("SOME_APP_SSL_KEY_PATH"),
  #         certfile: System.get_env("SOME_APP_SSL_CERT_PATH")
  #       ]
  #
  # The `cipher_suite` is set to `:strong` to support only the
  # latest and more secure SSL ciphers. This means old browsers
  # and clients may not be supported. You can set it to
  # `:compatible` for wider support.
  #
  # `:keyfile` and `:certfile` expect an absolute path to the key
  # and cert in disk or a relative path inside priv, for example
  # "priv/ssl/server.key". For all supported SSL configuration
  # options, see https://hexdocs.pm/plug/Plug.SSL.html#configure/1
  #
  # We also recommend setting `force_ssl` in your config/prod.exs,
  # ensuring no data is ever sent via http, always redirecting to https:
  #
  #     config :pki_ca_portal, PkiCaPortalWeb.Endpoint,
  #       force_ssl: [hsts: true]
  #
  # Check `Plug.SSL` for all available options in `force_ssl`.
end
