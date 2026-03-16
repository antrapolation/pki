import Config

config :pki_audit_trail, ecto_repos: [PkiAuditTrail.Repo]

import_config "#{config_env()}.exs"
