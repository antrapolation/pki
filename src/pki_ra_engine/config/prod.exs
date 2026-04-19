import Config

config :pki_ra_engine, PkiRaEngine.Repo,
  database: "pki_ra_engine_prod",
  pool_size: 10

config :logger, level: :info

config :logger, :console,
  format: "[$level] $time remote_ip=$metadata{remote_ip} $message\n",
  metadata: [:remote_ip, :module, :function]
