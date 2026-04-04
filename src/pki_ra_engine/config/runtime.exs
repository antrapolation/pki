import Config

# PlatformRepo config — pki_platform_engine is a dependency and needs its DB configured
if platform_db_url = System.get_env("PLATFORM_DATABASE_URL") || System.get_env("DATABASE_URL") do
  config :pki_platform_engine, PkiPlatformEngine.PlatformRepo,
    url: platform_db_url,
    pool_size: String.to_integer(System.get_env("POOL_SIZE", "5"))
end

# Production rate limiting: use Mnesia backend (survives restarts, works in clusters)
# Dev/test uses ETS (configured in config.exs)
if config_env() == :prod do
  config :hammer,
    backend: {Hammer.Backend.Mnesia, [expiry_ms: 60_000 * 60 * 2, cleanup_interval_ms: 60_000 * 10]}
end

if config_env() == :prod do
  database_url =
    System.get_env("RA_ENGINE_DATABASE_URL") ||
      System.get_env("DATABASE_URL") ||
      raise """
      environment variable RA_ENGINE_DATABASE_URL or DATABASE_URL is missing.
      For example: ecto://USER:PASS@HOST/DATABASE
      """

  # Parse URL into individual fields to ensure they override compile-time defaults
  db_config = Ecto.Repo.Supervisor.parse_url(database_url)

  config :pki_ra_engine, PkiRaEngine.Repo,
    Keyword.merge(db_config, pool_size: String.to_integer(System.get_env("POOL_SIZE") || "10"))

  # ── CA Engine connection (RA → CA signing flow) ────────────────────
  ca_engine_url =
    System.get_env("CA_ENGINE_URL") ||
      raise """
      environment variable CA_ENGINE_URL is missing.
      For example: http://pki-ca-engine:4001
      """

  internal_api_secret =
    System.get_env("INTERNAL_API_SECRET") ||
      raise """
      environment variable INTERNAL_API_SECRET is missing.
      This must match the value configured on the CA Engine.
      """

  config :pki_ra_engine,
    ca_engine_url: ca_engine_url,
    internal_api_secret: internal_api_secret,
    ca_engine_module: PkiRaEngine.CsrValidation.HttpCaClient
end
