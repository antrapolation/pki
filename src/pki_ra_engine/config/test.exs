import Config

config :logger, level: :warning

config :pki_ra_engine, start_dcv_poller: false
config :pki_ra_engine, ca_engine_module: PkiRaEngine.CsrValidation.DefaultCaClient
