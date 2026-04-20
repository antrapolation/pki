import Config

# pki_audit_trail still uses Postgres for centralized audit.
audit_repo_opts = [
  username: "postgres",
  password: System.get_env("POSTGRES_PASSWORD", "postgres"),
  hostname: "localhost",
  port: String.to_integer(System.get_env("POSTGRES_PORT", "5432")),
  database: System.get_env("AUDIT_TRAIL_DB", "pki_ca_engine_dev"),
  pool_size: 2
]

config :pki_audit_trail, PkiAuditTrail.Repo, audit_repo_opts

# Relax rate limiting in dev to avoid being blocked during debugging
config :pki_ca_engine, :rate_limit_enabled, false

# Allow dev_activate shortcut (bypasses ceremony) — NEVER enable in production
config :pki_ca_engine, :allow_dev_activate, true
