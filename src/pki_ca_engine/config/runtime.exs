import Config

if config_env() == :prod do
  database_url =
    System.get_env("DATABASE_URL") ||
      raise """
      environment variable DATABASE_URL is missing.
      For example: ecto://USER:PASS@HOST/DATABASE
      """

  db_config = Ecto.Repo.Supervisor.parse_url(database_url)

  config :pki_ca_engine, PkiCaEngine.Repo,
    Keyword.merge(db_config, pool_size: String.to_integer(System.get_env("POOL_SIZE") || "10"))

  # HTTP API server
  config :pki_ca_engine, :start_http, true
  config :pki_ca_engine, :http_port, String.to_integer(System.get_env("PORT") || "4001")

  # Internal API secret for service-to-service authentication
  config :pki_ca_engine,
         :internal_api_secret,
         System.get_env("INTERNAL_API_SECRET") ||
           raise("environment variable INTERNAL_API_SECRET is missing")

  # Validation service URL for certificate lifecycle notifications
  config :pki_ca_engine,
         :validation_url,
         System.get_env("VALIDATION_URL") ||
           raise("environment variable VALIDATION_URL is missing")
end
