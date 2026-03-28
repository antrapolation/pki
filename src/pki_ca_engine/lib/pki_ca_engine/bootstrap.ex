defmodule PkiCaEngine.Bootstrap do
  @moduledoc """
  Orchestrates the full tenant bootstrap when the first CA Admin sets up.

  Flow:
  1. Create CA Admin user with dual credentials (signing + KEM)
  2. Initialize Keypair ACL (encrypted with admin's KEM public key)
  3. Create 4 system keypairs (registered in Key Vault)
  """

  alias PkiCaEngine.{CredentialManager, KeypairACL, SystemKeypairs, Repo}

  def setup_tenant(ca_instance_id, admin_attrs, password, opts \\ []) do
    Repo.transaction(fn ->
      # 1. Create admin with credentials
      case CredentialManager.create_user_with_credentials(ca_instance_id, admin_attrs, password, opts) do
        {:ok, admin} ->
          # Get admin's KEM public key
          kem_cred = Enum.find(admin.credentials, &(&1.credential_type == "kem"))

          unless kem_cred do
            Repo.rollback(:missing_kem_credential)
          end

          # 2. Initialize ACL
          case KeypairACL.initialize(ca_instance_id, kem_cred.public_key, opts) do
            {:ok, acl_data} ->
              # 3. Create system keypairs
              {:ok, acl_public_keys} = KeypairACL.get_public_keys()

              case SystemKeypairs.create_all(ca_instance_id, acl_public_keys.kem_public_key, opts) do
                {:ok, system_kps} ->
                  %{
                    admin: admin,
                    acl: acl_data,
                    system_keypairs: system_kps
                  }

                {:error, reason} ->
                  Repo.rollback({:system_keypairs_failed, reason})
              end

            {:error, reason} ->
              Repo.rollback({:acl_init_failed, reason})
          end

        {:error, reason} ->
          Repo.rollback({:admin_creation_failed, reason})
      end
    end)
  end
end
