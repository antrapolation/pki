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

  ## Key hierarchy and domain separation (v1)

  The admin-decrypted ACL password is run through PBKDF2 (one iteration,
  since the password is high-entropy random) to produce the ACL *root key*.
  Each credential is wrapped with its own *sub-key*, derived from the root
  key via HKDF-SHA256 with a credential-type-scoped info tag:

      sub_key = HKDF(root_key, acl_salt, info: "pki_acl/v1/cred/\#{type}")

  Separate sub-keys per credential type (signing vs kem) close the
  domain-identical-function gap called out in the v1.1.0.0 security
  review: even if AES-GCM's random IVs prevent the immediate nonce-reuse
  collision, reusing one KEK across two distinct purposes is poor
  hygiene. A future bad-RNG or deterministic-nonce mistake cannot cause
  cross-credential key leakage, and the scheme is ready to version if
  additional credential types are added.

  Legacy ACLs (initialized before this scheme landed) wrapped both
  credentials with the raw root key. `activate/5` transparently falls
  back to the legacy scheme on decryption failure and logs a warning
  recommending re-initialization.
  """

  require Logger

  alias PkiCaEngine.Repo
  alias PkiCaEngine.Schema.CaUser
  alias PkiCaEngine.CredentialManager.Credential
  alias PkiCrypto.{Algorithm, Registry, Kdf, Symmetric}
  import Ecto.Query

  @acl_user_id "00000000-0000-0000-0000-000000000000"
  @scheme_version "v1"

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
    # Generate a random password for the ACL
    acl_password = :crypto.strong_rand_bytes(32)
    acl_salt = Kdf.generate_salt()
    # Low iterations — password is random high-entropy. This yields the ACL
    # root key; per-credential sub-keys are derived with HKDF below.
    case Kdf.derive_key(acl_password, acl_salt, iterations: 1) do
      {:ok, acl_root_key} ->
        do_initialize(ca_instance_id, admin_kem_public_key, acl_password, acl_salt, acl_root_key, opts)
      {:error, reason} ->
        {:error, {:kdf_failed, reason}}
    end
  end

  @doc """
  Derive a per-credential-type wrap key from the ACL root key using
  HKDF-SHA256 with a credential-type-scoped info tag. Pure function — the
  same inputs always yield the same wrap key.

  `credential_type` must be either `"signing"` or `"kem"`.
  """
  def derive_wrap_key(acl_root_key, acl_salt, credential_type)
      when is_binary(acl_root_key) and is_binary(acl_salt) and
             credential_type in ["signing", "kem"] do
    info = "pki_acl/" <> @scheme_version <> "/cred/" <> credential_type
    {:ok, wrap_key} = Kdf.hkdf(acl_root_key, acl_salt, info: info, length: 32)
    wrap_key
  end

  defp do_initialize(ca_instance_id, admin_kem_public_key, acl_password, acl_salt, acl_root_key, opts) do
    signing_algo = Keyword.get(opts, :signing_algorithm, "ECC-P256")
    kem_algo = Keyword.get(opts, :kem_algorithm, "ECDH-P256")

    Repo.transaction(fn ->
      # Ensure the virtual system user exists
      case ensure_system_user(ca_instance_id) do
        {:ok, _user} ->
          :ok

        {:error, reason} ->
          Repo.rollback({:system_user_failed, reason})
      end

      # Create ACL signing credential with a type-specific wrap key
      signing_wrap_key = derive_wrap_key(acl_root_key, acl_salt, "signing")

      signing_cred =
        case generate_and_store_credential("signing", signing_algo, signing_wrap_key, acl_salt) do
          {:ok, cred} -> cred
          {:error, reason} -> Repo.rollback({:signing_credential_failed, reason})
        end

      # Create ACL KEM credential with a type-specific wrap key
      kem_wrap_key = derive_wrap_key(acl_root_key, acl_salt, "kem")

      kem_cred =
        case generate_and_store_credential("kem", kem_algo, kem_wrap_key, acl_salt) do
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
         {:ok, acl_root_key} <- Kdf.derive_key(acl_password, acl_salt, iterations: 1) do
      signing_cred = get_acl_credential("signing")
      kem_cred = get_acl_credential("kem")

      with {:ok, signing_key} <- decrypt_acl_credential(signing_cred, acl_root_key, acl_salt),
           {:ok, kem_key} <- decrypt_acl_credential(kem_cred, acl_root_key, acl_salt) do
        {:ok, %{signing_key: signing_key, kem_key: kem_key}}
      end
    end
  end

  # Try v1 (HKDF-derived sub-key) first; fall back to legacy (raw root key
  # wrap). Legacy ACLs were created before the domain-separation fix
  # landed and must still decrypt until they're re-initialized.
  @doc false
  def decrypt_acl_credential(nil, _root_key, _salt), do: {:error, :credential_not_found}

  def decrypt_acl_credential(cred, acl_root_key, acl_salt) do
    wrap_key = derive_wrap_key(acl_root_key, acl_salt, cred.credential_type)

    case Symmetric.decrypt(cred.encrypted_private_key, wrap_key) do
      {:ok, key} ->
        {:ok, key}

      {:error, _} ->
        case Symmetric.decrypt(cred.encrypted_private_key, acl_root_key) do
          {:ok, key} ->
            Logger.warning(
              "ACL credential #{cred.credential_type} (id=#{cred.id}) decrypted via legacy " <>
                "pre-v1 wrap scheme. Re-initialize the ACL to move it to the HKDF-domain-separated scheme."
            )

            {:ok, key}

          {:error, _} = err ->
            err
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
