import Config

# PlatformRepo config — pki_platform_engine is a dependency and needs its DB configured.
if platform_db_url = System.get_env("PLATFORM_DATABASE_URL") || System.get_env("DATABASE_URL") do
  config :pki_platform_engine, PkiPlatformEngine.PlatformRepo,
    url: platform_db_url,
    pool_size: String.to_integer(System.get_env("POOL_SIZE", "5"))
end

# Production rate limiting: Mnesia backend (survives restarts, cluster-aware).
# Dev/test uses ETS (configured in config.exs).
if config_env() == :prod do
  config :hammer,
    backend: {Hammer.Backend.Mnesia, [expiry_ms: 60_000 * 60 * 2, cleanup_interval_ms: 60_000 * 10]}
end

if config_env() == :prod do
  # RA and CA share the BEAM in per-tenant deployments, so the CA
  # client is always the in-process direct variant.
  config :pki_ra_engine, ca_engine_module: PkiRaEngine.CsrValidation.DirectCaClient
end
