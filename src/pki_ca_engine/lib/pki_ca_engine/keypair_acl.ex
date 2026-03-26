defmodule PkiCaEngine.KeypairACL do
  @moduledoc """
  Manages the Keypair ACL — a special system credential that gates access
  to all operational keypairs via signed grant envelopes.

  The ACL holds two credentials:
  - Signing keypair — signs grant envelopes
  - KEM keypair — encrypts keypair activation passwords

  The ACL's private keys are encrypted with a random password. That random
  password is encrypted with the first CA Admin's KEM public key. To activate
  the ACL you need:
  1. The admin's KEM private key (decrypted via their session)
  2. Which decrypts the ACL's random password
  3. Which decrypts the ACL's signing + KEM private keys
  """

  alias PkiCaEngine.Repo
  alias PkiCaEngine.Schema.CaUser
  alias PkiCaEngine.CredentialManager.Credential
  alias PkiCrypto.{Algorithm, Registry, Kdf, Symmetric}
  import Ecto.Query

  @acl_user_id "00000000-0000-0000-0000-000000000000"

  @doc "The well-known UUID for the virtual ACL system user."
  def acl_user_id, do: @acl_user_id

  @doc "Check if the ACL has been initialized (has at least a signing credential)."
  def initialized?(ca_instance_id) do
    count =
      Repo.one(
        from c in Credential,
          join: u in CaUser,
          on: c.user_id == u.id,
          where:
            u.id == ^@acl_user_id and
              u.ca_instance_id == ^ca_instance_id and
              c.credential_type == "signing",
          select: count(c.id)
      )

    count > 0
  end

  @doc """
  Initialize the ACL. Creates a virtual system user and signing + KEM
  credentials for the ACL, encrypts their passwords with the admin's
  KEM public key.

  Returns `{:ok, %{acl_signing: credential, acl_kem: credential,
  encrypted_acl_password: binary, kem_ciphertext: binary, acl_salt: binary}}`
  """
  def initialize(ca_instance_id, admin_kem_public_key, opts \\ []) do
    signing_algo = Keyword.get(opts, :signing_algorithm, "ECC-P256")
    kem_algo = Keyword.get(opts, :kem_algorithm, "ECDH-P256")

    # Generate a random password for the ACL
    acl_password = :crypto.strong_rand_bytes(32)
    acl_salt = Kdf.generate_salt()
    # Low iterations — password is random high-entropy
    {:ok, acl_derived_key} = Kdf.derive_key(acl_password, acl_salt, iterations: 1)

    Repo.transaction(fn ->
      # Ensure the virtual system user exists
      case ensure_system_user(ca_instance_id) do
        {:ok, _user} ->
          :ok

        {:error, reason} ->
          Repo.rollback({:system_user_failed, reason})
      end

      # Create ACL signing credential
      signing_cred =
        case generate_and_store_credential("signing", signing_algo, acl_derived_key, acl_salt) do
          {:ok, cred} -> cred
          {:error, reason} -> Repo.rollback({:signing_credential_failed, reason})
        end

      # Create ACL KEM credential
      kem_cred =
        case generate_and_store_credential("kem", kem_algo, acl_derived_key, acl_salt) do
          {:ok, cred} -> cred
          {:error, reason} -> Repo.rollback({:kem_credential_failed, reason})
        end

      # Encrypt the ACL password with admin's KEM public key
      kem_struct = Registry.get(kem_algo)

      {shared_secret, ciphertext} =
        case Algorithm.kem_encapsulate(kem_struct, admin_kem_public_key) do
          {:ok, result} -> result
          {:error, reason} -> Repo.rollback({:kem_encapsulate_failed, reason})
        end

      encrypted_acl_password =
        case Symmetric.encrypt(acl_password, shared_secret) do
          {:ok, enc} -> enc
          {:error, reason} -> Repo.rollback({:encrypt_password_failed, reason})
        end

      %{
        acl_signing: signing_cred,
        acl_kem: kem_cred,
        encrypted_acl_password: encrypted_acl_password,
        kem_ciphertext: ciphertext,
        acl_salt: acl_salt
      }
    end)
  end

  @doc """
  Activate the ACL using the admin's KEM private key.
  Returns `{:ok, %{signing_key: binary, kem_key: binary}}` — the decrypted
  ACL private keys.
  """
  def activate(admin_kem_private_key, encrypted_acl_password, kem_ciphertext, acl_salt, kem_algo \\ "ECDH-P256") do
    kem_struct = Registry.get(kem_algo)

    with {:ok, shared_secret} <- Algorithm.kem_decapsulate(kem_struct, admin_kem_private_key, kem_ciphertext),
         {:ok, acl_password} <- Symmetric.decrypt(encrypted_acl_password, shared_secret),
         {:ok, acl_derived_key} <- Kdf.derive_key(acl_password, acl_salt, iterations: 1) do
      # Decrypt ACL signing key
      signing_cred = get_acl_credential("signing")
      kem_cred = get_acl_credential("kem")

      with {:ok, signing_key} <- Symmetric.decrypt(signing_cred.encrypted_private_key, acl_derived_key),
           {:ok, kem_key} <- Symmetric.decrypt(kem_cred.encrypted_private_key, acl_derived_key) do
        {:ok, %{signing_key: signing_key, kem_key: kem_key}}
      end
    end
  end

  @doc "Get the ACL's public keys."
  def get_public_keys do
    signing = get_acl_credential("signing")
    kem = get_acl_credential("kem")

    if signing && kem do
      {:ok, %{signing_public_key: signing.public_key, kem_public_key: kem.public_key}}
    else
      {:error, :not_initialized}
    end
  end

  # --- Private ---

  defp ensure_system_user(ca_instance_id) do
    case Repo.get(CaUser, @acl_user_id) do
      nil ->
        %CaUser{id: @acl_user_id}
        |> CaUser.changeset(%{
          ca_instance_id: ca_instance_id,
          username: "__acl_system__",
          display_name: "Keypair ACL System",
          role: "ca_admin",
          status: "active"
        })
        |> Repo.insert()

      user ->
        {:ok, user}
    end
  end

  defp generate_and_store_credential(type, algorithm, derived_key, salt) do
    algo = Registry.get(algorithm)

    with {:ok, %{public_key: pub, private_key: priv}} <- Algorithm.generate_keypair(algo),
         {:ok, encrypted_priv} <- Symmetric.encrypt(priv, derived_key) do
      %Credential{}
      |> Credential.changeset(%{
        user_id: @acl_user_id,
        credential_type: type,
        algorithm: algorithm,
        public_key: pub,
        encrypted_private_key: encrypted_priv,
        salt: salt,
        status: "active"
      })
      |> Repo.insert()
    end
  end

  defp get_acl_credential(type) do
    Repo.one(
      from c in Credential,
        where: c.user_id == ^@acl_user_id and c.credential_type == ^type and c.status == "active"
    )
  end
end
