import Config

ca_schema_prefix = System.get_env("CA_SCHEMA_PREFIX", "public")

ca_repo_opts = [
  username: "postgres",
  password: System.get_env("POSTGRES_PASSWORD", "postgres"),
  hostname: "localhost",
  port: String.to_integer(System.get_env("POSTGRES_PORT", "5432")),
  database: System.get_env("CA_ENGINE_DB", "pki_ca_engine_dev"),
  stacktrace: true,
  show_sensitive_data_on_connection_error: true,
  pool_size: 3
]

ca_repo_opts =
  if ca_schema_prefix != "public" do
    Keyword.put(ca_repo_opts, :after_connect, {Postgrex, :query!, ["SET search_path TO #{ca_schema_prefix}", []]})
  else
    ca_repo_opts
  end

config :pki_ca_engine, PkiCaEngine.Repo, ca_repo_opts

audit_repo_opts = [
  username: "postgres",
  password: System.get_env("POSTGRES_PASSWORD", "postgres"),
  hostname: "localhost",
  port: String.to_integer(System.get_env("POSTGRES_PORT", "5432")),
  database: System.get_env("AUDIT_TRAIL_DB", "pki_ca_engine_dev"),
  pool_size: 2
]

audit_repo_opts =
  if ca_schema_prefix != "public" do
    Keyword.put(audit_repo_opts, :after_connect, {Postgrex, :query!, ["SET search_path TO #{ca_schema_prefix}", []]})
  else
    audit_repo_opts
  end

config :pki_audit_trail, PkiAuditTrail.Repo, audit_repo_opts

# HTTP API server
config :pki_ca_engine, :start_http, true
config :pki_ca_engine, :http_port, String.to_integer(System.get_env("PORT", "4001"))
config :pki_ca_engine, :internal_api_secret, System.get_env("INTERNAL_API_SECRET", "dev-secret")
config :pki_ca_engine, :validation_url, System.get_env("VALIDATION_URL", "http://localhost:4005")
