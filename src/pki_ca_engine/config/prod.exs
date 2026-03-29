import Config

config :pki_ca_engine, PkiCaEngine.Repo,
  pool_size: 10

config :pki_ca_engine, []

config :logger, level: :info

config :logger, :console,
  format: "[$level] $time remote_ip=$metadata{remote_ip} $message\n",
  metadata: [:remote_ip, :module, :function]
