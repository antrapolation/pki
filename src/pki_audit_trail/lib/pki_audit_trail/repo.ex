defmodule PkiAuditTrail.Repo do
  use Ecto.Repo,
    otp_app: :pki_audit_trail,
    adapter: Ecto.Adapters.Postgres

  @impl true
  def default_options(_operation) do
    case Process.get(:pki_ecto_prefix) do
      nil -> []
      prefix -> [prefix: prefix]
    end
  end
end
