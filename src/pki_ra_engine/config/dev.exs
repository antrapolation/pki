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

# In-process CA engine integration (RA + CA share the same BEAM).
config :pki_ra_engine, ca_engine_module: PkiRaEngine.CsrValidation.DefaultCaClient
