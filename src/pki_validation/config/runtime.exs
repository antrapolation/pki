import Config

if config_env() == :prod do
  database_url =
    System.get_env("VALIDATION_DATABASE_URL") ||
      System.get_env("DATABASE_URL") ||
      raise """
      environment variable VALIDATION_DATABASE_URL or DATABASE_URL is missing.
      For example: ecto://USER:PASS@HOST/DATABASE
      """

  db_config = Ecto.Repo.Supervisor.parse_url(database_url)

  config :pki_validation,
         PkiValidation.Repo,
         Keyword.merge(db_config,
           pool_size: String.to_integer(System.get_env("POOL_SIZE") || "20")
         )

  # PlatformRepo used via pki_platform_engine dependency
  platform_database_url =
    System.get_env("PLATFORM_DATABASE_URL") ||
      System.get_env("DATABASE_URL") ||
      raise """
      environment variable PLATFORM_DATABASE_URL or DATABASE_URL is missing.
      """

  platform_db_config = Ecto.Repo.Supervisor.parse_url(platform_database_url)

  config :pki_platform_engine,
         PkiPlatformEngine.PlatformRepo,
         Keyword.merge(platform_db_config, pool_size: String.to_integer(System.get_env("PLATFORM_POOL_SIZE") || "5"))

  internal_api_secret = System.get_env("INTERNAL_API_SECRET")

  if is_nil(internal_api_secret) or internal_api_secret == "" do
    raise "environment variable INTERNAL_API_SECRET is missing or empty"
  end

  config :pki_validation, :internal_api_secret, internal_api_secret
end
