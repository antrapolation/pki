defmodule PkiCaEngine.Repo do
  use Ecto.Repo,
    otp_app: :pki_ca_engine,
    adapter: Ecto.Adapters.Postgres
end
