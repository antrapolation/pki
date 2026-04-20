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
#   pki_engines:  VALIDATION_PORT
#   pki_platform: PLATFORM_PORTAL_PORT, PHX_SERVER=true
#   pki_audit:    (minimal, just DATABASE_URL)

# ─── Database URLs ──────────────────────────────────────────────────────

database_url = System.get_env("DATABASE_URL")

platform_db_url = System.get_env("PLATFORM_DATABASE_URL") || database_url
audit_trail_db_url = System.get_env("AUDIT_TRAIL_DATABASE_URL") || database_url

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

# Base domain for Caddy route registration (e.g. "straptrust.com")
if base_domain = System.get_env("BASE_DOMAIN") do
  config :pki_platform_engine, base_domain: base_domain
end

# ─── Audit trail ────────────────────────────────────────────────────────

if audit_trail_db_url do
  config :pki_audit_trail, PkiAuditTrail.Repo,
    url: audit_trail_db_url,
    pool_size: String.to_integer(System.get_env("AUDIT_POOL_SIZE", "5")),
    prepare: :unnamed
end

# ─── Validation ─────────────────────────────────────────────────────────
# Validation (OCSP/CRL/TSA) is hosted inside each tenant BEAM on Mnesia.
# Its HTTP listener opts in via VALIDATION_START_HTTP=true / VALIDATION_PORT.
if System.get_env("VALIDATION_START_HTTP") == "true" do
  config :pki_validation, :http, start: true, port: String.to_integer(System.get_env("VALIDATION_PORT", "4005"))
end

# ─── Production-only configuration ──────────────────────────────────────

if config_env() == :prod do
  secret_key_base =
    System.get_env("SECRET_KEY_BASE") ||
      raise "environment variable SECRET_KEY_BASE is missing"

  # ── RA Engine config ──
  # RA + CA + Validation all share one tenant BEAM, so the in-process
  # DirectCaClient is the only supported backend.
  config :pki_ra_engine, ca_engine_module: PkiRaEngine.CsrValidation.DirectCaClient

  # ── Rate limiting (ETS — in-memory, per-node, no Mnesia setup needed) ──
  # Mnesia backend requires schema init and caused "Service temporarily unavailable"
  # errors when Mnesia wasn't ready. ETS is simpler and sufficient for single-node.
  config :hammer,
    backend: {Hammer.Backend.ETS, [expiry_ms: 60_000 * 60 * 2, cleanup_interval_ms: 60_000 * 10]}

  # ── Portal endpoint (only if PHX_SERVER=true) ──
  if System.get_env("PHX_SERVER") do
    config :pki_platform_portal, PkiPlatformPortalWeb.Endpoint, server: true
  end

  config :pki_platform_portal, PkiPlatformPortalWeb.Endpoint,
    http: [port: String.to_integer(System.get_env("PLATFORM_PORTAL_PORT", "4006")), ip: {0, 0, 0, 0, 0, 0, 0, 0}],
    url: [host: System.get_env("PLATFORM_HOST", System.get_env("PHX_HOST", "localhost")), port: 443, scheme: "https"],
    check_origin: [
      "https://#{System.get_env("PLATFORM_HOST", System.get_env("PHX_HOST", "localhost"))}",
      "http://#{System.get_env("PLATFORM_HOST", System.get_env("PHX_HOST", "localhost"))}"
    ],
    secret_key_base: secret_key_base

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
  config :pki_platform_portal, cookie_secure: true

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

# ─── Cluster formation for multi-host replication ──────────────────────
if primary_host = System.get_env("PRIMARY_HOSTNAME") do
  replica_host = System.get_env("REPLICA_HOSTNAME")
  hosts = [:"pki_platform@#{primary_host}"]
  hosts = if replica_host, do: hosts ++ [:"pki_replica@#{replica_host}"], else: hosts

  config :libcluster,
    topologies: [
      pki_cluster: [
        strategy: Cluster.Strategy.Epmd,
        config: [hosts: hosts]
      ]
    ]
end

# Allow dev_activate in non-production for testing convenience
if config_env() != :prod do
  config :pki_ca_engine, allow_dev_activate: true
end

# ─── HSM Gateway (Phase D) ───────────────────────────────────────────────
# Set HSM_GATEWAY_PORT (or HSM_GRPC_PORT) to enable the gRPC server for
# remote HSM agents. When not set, HsmGateway is not started (zero overhead
# for software-only tenants).
# Example: HSM_GATEWAY_PORT=9010
if hsm_port = System.get_env("HSM_GATEWAY_PORT") || System.get_env("HSM_GRPC_PORT") do
  config :pki_ca_engine, :hsm_gateway_port, String.to_integer(hsm_port)
end
