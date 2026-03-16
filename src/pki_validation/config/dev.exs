import Config

config :pki_validation, PkiValidation.Repo,
  database: "pki_validation_dev",
  show_sensitive_data_on_connection_error: true,
  pool_size: 10

config :pki_validation, :http, start: true
