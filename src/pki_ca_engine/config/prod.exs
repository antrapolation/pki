import Config

config :logger, level: :info

config :logger, :console,
  format: "[$level] $time remote_ip=$metadata{remote_ip} $message\n",
  metadata: [:remote_ip, :module, :function]
