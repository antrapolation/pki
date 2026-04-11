defmodule PkiCaEngine.Repo.Migrations.AddCsrFingerprintToIssuedCertificates do
  use Ecto.Migration

  def change do
    alter table(:issued_certificates) do
      add :csr_fingerprint, :string
    end

    # Prevent duplicate CSR signing per issuer key (only for active certs)
    # Must be unique_index to prevent race conditions between concurrent requests
    create unique_index(:issued_certificates, [:issuer_key_id, :csr_fingerprint],
      where: "csr_fingerprint IS NOT NULL AND status = 'active'",
      name: :issued_certificates_issuer_csr_fingerprint_active_idx
    )
  end
end
