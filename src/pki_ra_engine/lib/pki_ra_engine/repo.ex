defmodule PkiRaEngine.Repo do
  use Ecto.Repo,
    otp_app: :pki_ra_engine,
    adapter: Ecto.Adapters.Postgres
end
