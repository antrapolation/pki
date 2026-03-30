defmodule PkiPlatformEngine.TenantMetrics do
  alias PkiPlatformEngine.TenantRepo

  def get_metrics(tenant) do
    %{
      db_size: get_db_size(tenant.database_name),
      ca_users: safe_count(tenant, "ca", "SELECT count(*) FROM ca_users"),
      ra_users: safe_count(tenant, "ra", "SELECT count(*) FROM ra_users"),
      certificates_issued: safe_count(tenant, "ca", "SELECT count(*) FROM issued_certificates"),
      active_certificates: safe_count(tenant, "ca", "SELECT count(*) FROM issued_certificates WHERE status = 'active'"),
      pending_csrs: safe_count(tenant, "ra", "SELECT count(*) FROM csr_requests WHERE status = 'pending'")
    }
  rescue
    _ -> %{db_size: 0, ca_users: 0, ra_users: 0, certificates_issued: 0, active_certificates: 0, pending_csrs: 0}
  end

  defp get_db_size(database_name) do
    case Ecto.Adapters.SQL.query(
           PkiPlatformEngine.PlatformRepo,
           "SELECT pg_database_size($1)",
           [database_name]
         ) do
      {:ok, %{rows: [[size]]}} -> size
      _ -> 0
    end
  end

  defp safe_count(tenant, schema, query) do
    case TenantRepo.execute_sql(tenant, schema, query, []) do
      {:ok, %{rows: [[count]]}} -> count
      _ -> 0
    end
  end

  def format_bytes(bytes) when bytes < 1024, do: "#{bytes} B"
  def format_bytes(bytes) when bytes < 1_048_576, do: "#{Float.round(bytes / 1024, 1)} KB"
  def format_bytes(bytes) when bytes < 1_073_741_824, do: "#{Float.round(bytes / 1_048_576, 1)} MB"
  def format_bytes(bytes), do: "#{Float.round(bytes / 1_073_741_824, 1)} GB"
end
