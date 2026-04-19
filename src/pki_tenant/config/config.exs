import Config

# Hammer rate limiter (ETS backend — in-memory, per-node)
config :hammer,
  backend:
    {Hammer.Backend.ETS, [expiry_ms: 60_000 * 60 * 2, cleanup_interval_ms: 60_000 * 10]}

import_config "#{config_env()}.exs"
