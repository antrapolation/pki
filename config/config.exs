import Config

# Compile-time configuration shared across all releases.
# Runtime configuration is in config/runtime.exs.

config :pki_system, env: config_env()

# JSON logging in production
if config_env() == :prod do
  config :logger, backends: [LoggerJSON]
  config :logger_json, :backend, metadata: :all
end
