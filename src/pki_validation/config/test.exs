import Config

config :pki_validation, PkiValidation.Repo,
  database: "pki_validation_test#{System.get_env("MIX_TEST_PARTITION")}",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 10

config :pki_validation, :http, start: false

config :logger, level: :warning
