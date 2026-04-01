import Config

config :pki_validation, PkiValidation.Repo,
  username: "postgres",
  password: System.get_env("POSTGRES_PASSWORD", "postgres"),
  hostname: "localhost",
  port: String.to_integer(System.get_env("POSTGRES_PORT", "5432")),
  database: System.get_env("VALIDATION_DB", "pki_validation_dev"),
  show_sensitive_data_on_connection_error: true,
  pool_size: 3

config :pki_validation, :http, start: true
config :pki_validation, :http_port, String.to_integer(System.get_env("PORT", "4005"))
config :pki_validation, :internal_api_secret, System.get_env("INTERNAL_API_SECRET", "dev-secret")
