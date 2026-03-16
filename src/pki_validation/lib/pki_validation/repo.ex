defmodule PkiValidation.Repo do
  use Ecto.Repo,
    otp_app: :pki_validation,
    adapter: Ecto.Adapters.Postgres
end
