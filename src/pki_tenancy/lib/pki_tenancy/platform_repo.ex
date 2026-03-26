defmodule PkiTenancy.PlatformRepo do
  use Ecto.Repo,
    otp_app: :pki_tenancy,
    adapter: Ecto.Adapters.Postgres
end
