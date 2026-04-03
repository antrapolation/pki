import Config

ra_schema_prefix = System.get_env("RA_SCHEMA_PREFIX", "public")

ra_repo_opts = [
  username: "postgres",
  password: System.get_env("POSTGRES_PASSWORD", "postgres"),
  hostname: "localhost",
  port: String.to_integer(System.get_env("POSTGRES_PORT", "5432")),
  database: System.get_env("RA_ENGINE_DB", "pki_ra_engine_dev"),
  stacktrace: true,
  show_sensitive_data_on_connection_error: true,
  pool_size: 3
]

ra_repo_opts =
  if ra_schema_prefix != "public" do
    Keyword.put(ra_repo_opts, :after_connect, {Postgrex, :query!, ["SET search_path TO #{ra_schema_prefix}", []]})
  else
    ra_repo_opts
  end

config :pki_ra_engine, PkiRaEngine.Repo, ra_repo_opts

config :pki_ra_engine, start_http: true
config :pki_ra_engine, :http_port, String.to_integer(System.get_env("PORT", "4003"))

# CA Engine connection defaults for local development.
config :pki_ra_engine,
  ca_engine_url: System.get_env("CA_ENGINE_URL", "http://localhost:4001"),
  internal_api_secret: System.get_env("INTERNAL_API_SECRET", "dev-secret"),
  ca_engine_module: PkiRaEngine.CsrValidation.DefaultCaClient

# Relax rate limiting in dev to avoid being blocked during debugging
config :pki_ra_engine, :rate_limit_enabled, false
