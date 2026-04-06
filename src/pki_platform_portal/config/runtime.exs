import Config

# config/runtime.exs is executed for all environments, including
# during releases. It is executed after compilation and before the
# system starts, so it is typically used to load production configuration
# and secrets from environment variables or elsewhere.

if System.get_env("PHX_SERVER") do
  config :pki_platform_portal, PkiPlatformPortalWeb.Endpoint, server: true
end

config :pki_platform_portal, PkiPlatformPortalWeb.Endpoint,
  http: [port: String.to_integer(System.get_env("PORT", "4006"))]

if config_env() != :prod do
  # Dev/test: allow defaults for convenience (hashed at Application.start)
  config :pki_platform_portal,
    admin_username: System.get_env("PLATFORM_ADMIN_USERNAME", "admin"),
    admin_password: System.get_env("PLATFORM_ADMIN_PASSWORD", "admin")
end

# PlatformRepo config — used by Provisioner for tenant database creation.
# Shares the same DATABASE_URL as the portal's own repo.
database_url = System.get_env("PLATFORM_DATABASE_URL") || System.get_env("DATABASE_URL")
if database_url do
  config :pki_platform_engine, PkiPlatformEngine.PlatformRepo,
    url: database_url,
    pool_size: String.to_integer(System.get_env("POOL_SIZE", "5"))
end

if config_env() == :prod do
  admin_username =
    System.get_env("PLATFORM_ADMIN_USERNAME") ||
      raise "environment variable PLATFORM_ADMIN_USERNAME is missing"

  # Accept either a pre-hashed Argon2 value (PLATFORM_ADMIN_PASSWORD_HASH)
  # or a plaintext value (PLATFORM_ADMIN_PASSWORD) that will be hashed at startup.
  # Prefer the hash to keep the plaintext out of application config entirely.
  admin_password_hash = System.get_env("PLATFORM_ADMIN_PASSWORD_HASH")
  admin_password = System.get_env("PLATFORM_ADMIN_PASSWORD")

  unless admin_password_hash || admin_password do
    raise "either PLATFORM_ADMIN_PASSWORD_HASH or PLATFORM_ADMIN_PASSWORD must be set"
  end

  config :pki_platform_portal, admin_username: admin_username

  if admin_password_hash do
    config :pki_platform_portal, admin_password_hash: admin_password_hash
  else
    config :pki_platform_portal, admin_password: admin_password
  end

  secret_key_base =
    System.get_env("SECRET_KEY_BASE") ||
      raise """
      environment variable SECRET_KEY_BASE is missing.
      You can generate one by calling: mix phx.gen.secret
      """

  host = System.get_env("PLATFORM_HOST") || System.get_env("PHX_HOST") || "example.com"

  config :pki_platform_portal, :dns_cluster_query, System.get_env("DNS_CLUSTER_QUERY")

  config :pki_platform_portal, PkiPlatformPortalWeb.Endpoint,
    url: [host: host, port: 443, scheme: "https"],
    check_origin: false,
    http: [
      ip: {0, 0, 0, 0, 0, 0, 0, 0}
    ],
    secret_key_base: secret_key_base
end
