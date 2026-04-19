import Config

config :pki_replica,
  primary_platform_node: :"pki_platform@server1",
  heartbeat_interval_ms: 5_000,
  heartbeat_failure_threshold: 3,
  webhook_url: nil,
  alert_log_path: "/var/log/pki/failover-alert.log"

# Hammer rate limiter config (required by transitive deps)
config :hammer,
  backend:
    {Hammer.Backend.ETS,
     [expiry_ms: 60_000 * 60 * 2, cleanup_interval_ms: 60_000 * 10]}

if Mix.env() == :test do
  # Disable real application startup in tests
  config :pki_replica, start_application: false
  config :pki_tenant, start_application: false
end
