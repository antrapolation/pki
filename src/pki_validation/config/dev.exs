import Config

config :pki_validation, :http, start: true
config :pki_validation, :http_port, String.to_integer(System.get_env("PORT", "4005"))
config :pki_validation, :internal_api_secret, System.get_env("INTERNAL_API_SECRET", "dev-secret")
