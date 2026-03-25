import Config

config :pki_ca_engine, PkiCaEngine.Repo,
  pool_size: 10

config :pki_ca_engine,
  crypto_adapter: PkiCaEngine.KeyCeremony.DefaultCryptoAdapter
