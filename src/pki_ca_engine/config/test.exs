import Config

config :pki_ca_engine, PkiCaEngine.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  database: "pki_ca_engine_test",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 10

config :logger, level: :warning
