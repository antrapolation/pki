import Config

config :pki_validation, PkiValidation.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: 5432,
  database: "pki_validation_dev",
  show_sensitive_data_on_connection_error: true,
  pool_size: 10

config :pki_validation, :http, start: true
config :pki_validation, :internal_api_secret, "dev-secret"
