import Config

config :pki_ra_engine, PkiRaEngine.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: 5434,
  database: "pki_ra_engine_test#{System.get_env("MIX_TEST_PARTITION")}",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 10

config :logger, level: :warning

config :pki_ra_engine, start_http: false
config :pki_ra_engine, start_dcv_poller: false
config :pki_ra_engine, start_csr_reconciler: false

config :pki_ra_engine,
  internal_api_secret: "test-secret",
  ca_engine_module: PkiRaEngine.CsrValidation.DefaultCaClient
