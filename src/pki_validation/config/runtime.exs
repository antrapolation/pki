import Config

if config_env() == :prod do
  database_url =
    System.get_env("DATABASE_URL") ||
      raise """
      environment variable DATABASE_URL is missing.
      For example: ecto://USER:PASS@HOST/DATABASE
      """

  db_config = Ecto.Repo.Supervisor.parse_url(database_url)

  config :pki_validation, PkiValidation.Repo,
    Keyword.merge(db_config, pool_size: String.to_integer(System.get_env("POOL_SIZE") || "20"))

  config :pki_validation,
         :internal_api_secret,
         System.get_env("INTERNAL_API_SECRET") ||
           raise("environment variable INTERNAL_API_SECRET is missing")
end
