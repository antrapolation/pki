defmodule PkiRaEngine.Repo.Migrations.SimplifyServiceConfigs do
  use Ecto.Migration

  def change do
    # Normalize existing service_type values to snake_case
    execute "UPDATE service_configs SET service_type = 'ocsp_responder' WHERE service_type IN ('OCSP Responder', 'ocsp')", ""
    execute "UPDATE service_configs SET service_type = 'crl_distribution' WHERE service_type IN ('CRL Distribution', 'crl')", ""
    execute "UPDATE service_configs SET service_type = 'tsa' WHERE service_type = 'TSA'", ""
    execute "UPDATE service_configs SET service_type = 'csr_web' WHERE service_type = 'csr_web'", ""
  end
end
