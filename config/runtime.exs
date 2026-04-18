import Config

# ─── Consolidated runtime configuration for all 3 releases ──────────────
#
# This file configures ALL services. Each release reads the same file;
# environment variables control which subsystems activate.
#
# Required env vars (all releases):
#   DATABASE_URL or individual *_DATABASE_URL vars
#   SECRET_KEY_BASE
#   INTERNAL_API_SECRET
#
# Release-specific env vars:
#   pki_engines:  CA_ENGINE_PORT, RA_ENGINE_PORT, VALIDATION_PORT
#   pki_portals:  CA_PORTAL_PORT, RA_PORTAL_PORT, PLATFORM_PORTAL_PORT,
#                 ENGINE_CLIENT_MODE=direct, PHX_SERVER=true
#   pki_audit:    (minimal, just DATABASE_URL)

# ─── Database URLs ──────────────────────────────────────────────────────

database_url = System.get_env("DATABASE_URL")

platform_db_url = System.get_env("PLATFORM_DATABASE_URL") || database_url
ca_engine_db_url = System.get_env("CA_ENGINE_DATABASE_URL") || database_url
ra_engine_db_url = System.get_env("RA_ENGINE_DATABASE_URL") || database_url
validation_db_url = System.get_env("VALIDATION_DATABASE_URL") || database_url
# Audit trail defaults to CA engine DB for backward compat (audit_events table lives there)
audit_trail_db_url = System.get_env("AUDIT_TRAIL_DATABASE_URL") || ca_engine_db_url

# ─── Platform Engine (all releases) ────────────────────────────────────

if platform_db_url do
  config :pki_platform_engine, PkiPlatformEngine.PlatformRepo,
    url: platform_db_url,
    pool_size: String.to_integer(System.get_env("PLATFORM_POOL_SIZE", "5")),
    prepare: :unnamed
end

# TenantRepo base config — credentials for dynamic per-tenant pools.
# Parse from PLATFORM_DATABASE_URL so tenant repos connect to the same server.
tenant_base =
  if platform_db_url do
    try do
      Ecto.Repo.Supervisor.parse_url(platform_db_url)
    rescue
      _ -> []
    end
  else
    []
  end

config :pki_platform_engine, PkiPlatformEngine.TenantRepo,
  hostname: System.get_env("POSTGRES_HOST", Keyword.get(tenant_base, :hostname, "127.0.0.1")),
  port: String.to_integer(System.get_env("POSTGRES_PORT", to_string(Keyword.get(tenant_base, :port, 5432)))),
  direct_port: String.to_integer(System.get_env("POSTGRES_DIRECT_PORT", to_string(Keyword.get(tenant_base, :port, 5432)))),
  username: System.get_env("POSTGRES_USER", Keyword.get(tenant_base, :username, "postgres")),
  password: System.get_env("POSTGRES_PASSWORD", Keyword.get(tenant_base, :password, "postgres"))

# Replica node for multi-host replication (optional)
if replica = System.get_env("REPLICA_NODE") do
  config :pki_platform_engine, replica_node: String.to_atom(replica)
end

# ─── CA Engine ──────────────────────────────────────────────────────────

if ca_engine_db_url do
  config :pki_ca_engine, PkiCaEngine.Repo,
    url: ca_engine_db_url,
    pool_size: String.to_integer(System.get_env("POOL_SIZE", "10")),
    prepare: :unnamed
end

if audit_trail_db_url do
  config :pki_audit_trail, PkiAuditTrail.Repo,
    url: audit_trail_db_url,
    pool_size: String.to_integer(System.get_env("AUDIT_POOL_SIZE", "5")),
    prepare: :unnamed
end

# CA Engine HTTP API — only starts if start_http is true (engines release)
if System.get_env("CA_ENGINE_START_HTTP") == "true" do
  config :pki_ca_engine, :start_http, true
  config :pki_ca_engine, :http_port,
    String.to_integer(System.get_env("CA_ENGINE_PORT", "4001"))
end

# ─── RA Engine ──────────────────────────────────────────────────────────

if ra_engine_db_url do
  config :pki_ra_engine, PkiRaEngine.Repo,
    url: ra_engine_db_url,
    pool_size: String.to_integer(System.get_env("POOL_SIZE", "10")),
    prepare: :unnamed
end

# RA Engine HTTP API — only starts if start_http is true (engines release)
if System.get_env("RA_ENGINE_START_HTTP") == "true" do
  config :pki_ra_engine, start_http: true
  config :pki_ra_engine, :http_port,
    String.to_integer(System.get_env("RA_ENGINE_PORT", "4003"))
end

# ─── Validation ─────────────────────────────────────────────────────────

if validation_db_url do
  config :pki_validation, PkiValidation.Repo,
    url: validation_db_url,
    pool_size: String.to_integer(System.get_env("VALIDATION_POOL_SIZE", "20")),
    prepare: :unnamed
end

# Validation HTTP API — only starts if VALIDATION_START_HTTP is true (engines release)
if System.get_env("VALIDATION_START_HTTP") == "true" do
  config :pki_validation, :http, start: true, port: String.to_integer(System.get_env("VALIDATION_PORT", "4005"))
end

# ─── Production-only configuration ──────────────────────────────────────

if config_env() == :prod do
  internal_api_secret =
    System.get_env("INTERNAL_API_SECRET") ||
      raise "environment variable INTERNAL_API_SECRET is missing"

  secret_key_base =
    System.get_env("SECRET_KEY_BASE") ||
      raise "environment variable SECRET_KEY_BASE is missing"

  validation_url = System.get_env("VALIDATION_URL", "http://localhost:4005")
  ca_engine_url = System.get_env("CA_ENGINE_URL", "http://localhost:4001")
  ra_engine_url = System.get_env("RA_ENGINE_URL", "http://localhost:4003")

  # ── CA Engine config ──
  config :pki_ca_engine,
    internal_api_secret: internal_api_secret,
    validation_url: validation_url

  # ── RA Engine config ──
  ca_engine_module =
    if System.get_env("ENGINE_CLIENT_MODE") == "direct" do
      PkiRaEngine.CsrValidation.DirectCaClient
    else
      PkiRaEngine.CsrValidation.HttpCaClient
    end

  config :pki_ra_engine,
    ca_engine_url: ca_engine_url,
    internal_api_secret: internal_api_secret,
    ca_engine_module: ca_engine_module

  # ── Rate limiting (ETS — in-memory, per-node, no Mnesia setup needed) ──
  # Mnesia backend requires schema init and caused "Service temporarily unavailable"
  # errors when Mnesia wasn't ready. ETS is simpler and sufficient for single-node.
  config :hammer,
    backend: {Hammer.Backend.ETS, [expiry_ms: 60_000 * 60 * 2, cleanup_interval_ms: 60_000 * 10]}

  # ── Portal endpoints (only if PHX_SERVER=true) ──
  if System.get_env("PHX_SERVER") do
    config :pki_ca_portal, PkiCaPortalWeb.Endpoint, server: true
    config :pki_ra_portal, PkiRaPortalWeb.Endpoint, server: true
    config :pki_platform_portal, PkiPlatformPortalWeb.Endpoint, server: true
  end

  config :pki_ca_portal, PkiCaPortalWeb.Endpoint,
    http: [port: String.to_integer(System.get_env("CA_PORTAL_PORT", "4002")), ip: {0, 0, 0, 0, 0, 0, 0, 0}],
    url: [host: System.get_env("CA_PORTAL_HOST", System.get_env("PHX_HOST", "localhost")), port: 443, scheme: "https"],
    check_origin: [
      "https://#{System.get_env("CA_PORTAL_HOST", System.get_env("PHX_HOST", "localhost"))}",
      "http://#{System.get_env("CA_PORTAL_HOST", System.get_env("PHX_HOST", "localhost"))}"
    ],
    secret_key_base: secret_key_base

  config :pki_ra_portal, PkiRaPortalWeb.Endpoint,
    http: [port: String.to_integer(System.get_env("RA_PORTAL_PORT", "4004")), ip: {0, 0, 0, 0, 0, 0, 0, 0}],
    url: [host: System.get_env("RA_PORTAL_HOST", System.get_env("PHX_HOST", "localhost")), port: 443, scheme: "https"],
    check_origin: [
      "https://#{System.get_env("RA_PORTAL_HOST", System.get_env("PHX_HOST", "localhost"))}",
      "http://#{System.get_env("RA_PORTAL_HOST", System.get_env("PHX_HOST", "localhost"))}"
    ],
    secret_key_base: secret_key_base

  config :pki_platform_portal, PkiPlatformPortalWeb.Endpoint,
    http: [port: String.to_integer(System.get_env("PLATFORM_PORTAL_PORT", "4006")), ip: {0, 0, 0, 0, 0, 0, 0, 0}],
    url: [host: System.get_env("PLATFORM_HOST", System.get_env("PHX_HOST", "localhost")), port: 443, scheme: "https"],
    check_origin: [
      "https://#{System.get_env("PLATFORM_HOST", System.get_env("PHX_HOST", "localhost"))}",
      "http://#{System.get_env("PLATFORM_HOST", System.get_env("PHX_HOST", "localhost"))}"
    ],
    secret_key_base: secret_key_base

  # ── CA Portal engine client ──
  ca_portal_client =
    case System.get_env("ENGINE_CLIENT_MODE") do
      "direct" -> PkiCaPortal.CaEngineClient.Direct
      _ -> PkiCaPortal.CaEngineClient.Http
    end

  ca_portal_url = System.get_env("CA_PORTAL_URL", "https://#{System.get_env("CA_PORTAL_HOST", "localhost")}")

  config :pki_ca_portal,
    ca_engine_client: ca_portal_client,
    ca_engine_url: ca_engine_url,
    internal_api_secret: internal_api_secret,
    portal_url: ca_portal_url

  # ── RA Portal engine client ──
  ra_portal_client =
    case System.get_env("ENGINE_CLIENT_MODE") do
      "direct" -> PkiRaPortal.RaEngineClient.Direct
      _ -> PkiRaPortal.RaEngineClient.Http
    end

  ra_portal_url = System.get_env("RA_PORTAL_URL", "https://#{System.get_env("RA_PORTAL_HOST", "localhost")}")

  config :pki_ra_portal,
    ra_engine_client: ra_portal_client,
    ra_engine_url: ra_engine_url,
    internal_api_secret: internal_api_secret,
    portal_url: ra_portal_url

  # ── Platform Portal admin credentials ──
  admin_username = System.get_env("PLATFORM_ADMIN_USERNAME") ||
    raise "environment variable PLATFORM_ADMIN_USERNAME is missing"

  admin_password_hash = System.get_env("PLATFORM_ADMIN_PASSWORD_HASH")

  unless admin_password_hash do
    raise """
    environment variable PLATFORM_ADMIN_PASSWORD_HASH is required in production.
    Generate it with: mix phx.gen.secret | xargs -I{} elixir -e 'IO.puts(Bcrypt.hash_pwd_salt("{}"))'
    """
  end

  config :pki_platform_portal,
    admin_username: admin_username,
    admin_password_hash: admin_password_hash

  if signing_salt = System.get_env("PLATFORM_SIGNING_SALT") do
    config :pki_platform_portal, signing_salt: signing_salt
  end

  # ── Cookie security (always secure in production) ──
  config :pki_ca_portal, cookie_secure: true
  config :pki_ra_portal, cookie_secure: true
  config :pki_platform_portal, cookie_secure: true

  # ── Session encryption salts (override hardcoded defaults in production) ──
  if enc_salt = System.get_env("CA_PORTAL_ENCRYPTION_SALT") do
    config :pki_ca_portal, encryption_salt: enc_salt
  end

  if enc_salt = System.get_env("RA_PORTAL_ENCRYPTION_SALT") do
    config :pki_ra_portal, encryption_salt: enc_salt
  end

  if enc_salt = System.get_env("PLATFORM_ENCRYPTION_SALT") do
    config :pki_platform_portal, encryption_salt: enc_salt
  end
end

# ─── Tenant Node (pki_tenant_node release) ──────────────────────────────
# Tenant nodes read their config from env vars set by the platform's
# TenantLifecycle when spawning via :peer module.

if tenant_port = System.get_env("TENANT_PORT") do
  config :pki_tenant_web, PkiTenantWeb.Endpoint,
    http: [port: String.to_integer(tenant_port)],
    server: true

  if config_env() == :prod do
    secret =
      System.get_env("SECRET_KEY_BASE") ||
        raise "SECRET_KEY_BASE is required for tenant nodes in production"

    config :pki_tenant_web, PkiTenantWeb.Endpoint,
      secret_key_base: secret
  else
    if secret = System.get_env("SECRET_KEY_BASE") do
      config :pki_tenant_web, PkiTenantWeb.Endpoint,
        secret_key_base: secret
    end
  end

  base_domain = System.get_env("TENANT_BASE_DOMAIN", "localhost")
  if tenant_slug = System.get_env("TENANT_SLUG") do
    config :pki_tenant_web, PkiTenantWeb.Endpoint,
      url: [host: "#{tenant_slug}.ca.#{base_domain}"]
  end
end

if mnesia_dir = System.get_env("MNESIA_DIR") do
  config :pki_tenant, mnesia_dir: mnesia_dir
end

if platform_node = System.get_env("PLATFORM_NODE") do
  config :pki_tenant, platform_node: platform_node
end

if tenant_id = System.get_env("TENANT_ID") do
  config :pki_tenant, tenant_id: tenant_id
end

# Allow dev_activate in non-production for testing convenience
if config_env() != :prod do
  config :pki_ca_engine, allow_dev_activate: true
end
