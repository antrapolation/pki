import Config

if config_env() == :prod do
  # pki_audit_trail and pki_platform_engine still use Postgres.
  database_url =
    System.get_env("AUDIT_TRAIL_DATABASE_URL") ||
      System.get_env("DATABASE_URL") ||
      raise """
      environment variable AUDIT_TRAIL_DATABASE_URL or DATABASE_URL is missing.
      """

  db_config = Ecto.Repo.Supervisor.parse_url(database_url)

  config :pki_audit_trail, PkiAuditTrail.Repo,
    Keyword.merge(db_config, pool_size: String.to_integer(System.get_env("AUDIT_POOL_SIZE") || "5"))

  platform_database_url =
    System.get_env("PLATFORM_DATABASE_URL") ||
      System.get_env("DATABASE_URL") ||
      raise """
      environment variable PLATFORM_DATABASE_URL or DATABASE_URL is missing.
      """

  platform_db_config = Ecto.Repo.Supervisor.parse_url(platform_database_url)

  config :pki_platform_engine, PkiPlatformEngine.PlatformRepo,
    Keyword.merge(platform_db_config, pool_size: String.to_integer(System.get_env("PLATFORM_POOL_SIZE") || "5"))
end
