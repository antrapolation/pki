import Config

config :pki_validation, PkiValidation.Repo,
  database: "pki_validation_prod",
  pool_size: 20

config :pki_validation, :http, start: true
