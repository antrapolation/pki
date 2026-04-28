import Config

config :pki_validation, :http, port: 4005

import_config "#{config_env()}.exs"
