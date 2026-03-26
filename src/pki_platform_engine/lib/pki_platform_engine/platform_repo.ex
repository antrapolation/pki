defmodule PkiPlatformEngine.PlatformRepo do
  use Ecto.Repo,
    otp_app: :pki_platform_engine,
    adapter: Ecto.Adapters.Postgres
end
