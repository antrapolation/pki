defmodule PkiRaEngine.Repo.Migrations.CreateCertProfiles do
  use Ecto.Migration

  def change do
    create table(:cert_profiles) do
      add :name, :string, null: false
      add :subject_dn_policy, :map, default: %{}
      add :issuer_policy, :map, default: %{}
      add :key_usage, :string
      add :ext_key_usage, :string
      add :digest_algo, :string
      add :validity_policy, :map, default: %{}
      add :timestamping_policy, :map, default: %{}
      add :crl_policy, :map, default: %{}
      add :ocsp_policy, :map, default: %{}
      add :ca_repository_url, :string
      add :issuer_url, :string
      add :included_extensions, :map, default: %{}
      add :renewal_policy, :map, default: %{}
      add :notification_profile, :map, default: %{}
      add :cert_publish_policy, :map, default: %{}

      timestamps()
    end

    create unique_index(:cert_profiles, [:name])
  end
end
