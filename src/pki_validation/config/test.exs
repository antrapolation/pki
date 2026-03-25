import Config

config :pki_validation, PkiValidation.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: 5432,
  database: "pki_validation_test#{System.get_env("MIX_TEST_PARTITION")}",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 10

config :pki_validation, :http, start: false
config :pki_validation, :internal_api_secret, "test-secret"

config :logger, level: :warning
