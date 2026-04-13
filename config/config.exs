import Config

# Compile-time configuration shared across all releases.
# Runtime configuration is in config/runtime.exs.

config :pki_system, env: config_env()

# JSON logging in production (LoggerJSON 6.x uses formatter API, not backends)
if config_env() == :prod do
  config :logger, :default_handler,
    formatter: {LoggerJSON.Formatters.Basic, metadata: :all}
end
