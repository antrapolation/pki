defmodule PkiAuditTrail.Repo do
  use Ecto.Repo,
    otp_app: :pki_audit_trail,
    adapter: Ecto.Adapters.Postgres
end
