import Config

# In-process CA engine integration (RA + CA share the same BEAM).
config :pki_ra_engine, ca_engine_module: PkiRaEngine.CsrValidation.DefaultCaClient
