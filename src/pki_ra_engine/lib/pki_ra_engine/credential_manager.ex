defmodule PkiRaEngine.CredentialManager do
  @moduledoc """
  Manages user credentials (dual signing + KEM keypairs) for the RA Engine.

  Every user in the system has two cryptographic credentials:
  - Signing credential: for digital signatures and attestations
  - KEM credential: for key encapsulation (encrypting secrets for the user)
  """

  alias PkiRaEngine.Repo
  alias PkiRaEngine.Schema.RaUser
  alias PkiRaEngine.CredentialManager.Credential
  alias PkiCrypto.{KeyOps, Kdf}
  import Ecto.Query

  @doc """
  Create a user with dual credentials (signing + KEM keypairs).
  The private keys are encrypted with a key derived from the user's password.
  """
  def create_user_with_credentials(user_attrs, password, opts \\ []) do
    signing_algo = Keyword.get(opts, :signing_algorithm, "ECC-P256")
    kem_algo = Keyword.get(opts, :kem_algorithm, "ECDH-P256")

    Repo.transaction(fn ->
      # 1. Create the user record
      user_changeset =
        RaUser.registration_changeset(
          %RaUser{},
          Map.merge(user_attrs, %{password: password})
        )

      case Repo.insert(user_changeset) do
        {:ok, user} ->
          # 2. Generate signing credential
          case create_credential(user.id, "signing", signing_algo, password) do
            {:ok, _signing_cred} ->
              # TODO(attestation): After creating signing credential, call attestation
              # when the admin has an active session with a session_key:
              #   PkiCrypto.Attestation.attest(admin_signing_key, admin_algorithm, signing_pub_key)
              # This requires the admin's decrypted signing key, which is not available
              # in the bootstrap flow. Wire this into the manual user creation flow
              # where the admin's session_key is passed through the API.

              # 3. Generate KEM credential
              case create_credential(user.id, "kem", kem_algo, password) do
                {:ok, _kem_cred} ->
                  Repo.preload(user, :credentials)

                {:error, reason} ->
                  Repo.rollback({:kem_credential_failed, reason})
              end

            {:error, reason} ->
              Repo.rollback({:signing_credential_failed, reason})
          end

        {:error, changeset} ->
          Repo.rollback(changeset)
      end
    end)
  end

  @doc """
  Authenticate a user by verifying password hash AND key ownership.
  Returns {:ok, user, session_info} or {:error, :invalid_credentials}.
  """
  def authenticate(username, password) do
    user =
      Repo.one(
        from u in RaUser,
          where: u.username == ^username and u.status == "active",
          preload: [:credentials]
      )

    case user do
      nil ->
        # Timing-safe: do a dummy hash check to prevent timing attacks
        Argon2.no_user_verify()
        {:error, :invalid_credentials}

      user ->
        if Argon2.verify_pass(password, user.password_hash) do
          # Verify key ownership by attempting to decrypt signing key
          signing_cred = Enum.find(user.credentials, &(&1.credential_type == "signing"))

          if signing_cred &&
               KeyOps.verify_key_ownership(
                 signing_cred.encrypted_private_key,
                 signing_cred.salt,
                 password
               ) do
            # Generate session key for this login session
            session_salt = Kdf.generate_salt()
            {:ok, session_key} = Kdf.derive_key(password, session_salt)
            {:ok, user, %{session_key: session_key, session_salt: session_salt}}
          else
            {:error, :invalid_credentials}
          end
        else
          {:error, :invalid_credentials}
        end
    end
  end

  @doc "Get a user's signing credential."
  def get_signing_credential(user_id) do
    Repo.one(
      from c in Credential,
        where: c.user_id == ^user_id and c.credential_type == "signing" and c.status == "active"
    )
  end

  @doc "Get a user's KEM credential."
  def get_kem_credential(user_id) do
    Repo.one(
      from c in Credential,
        where: c.user_id == ^user_id and c.credential_type == "kem" and c.status == "active"
    )
  end

  @doc "Sign data using a user's signing key (decrypted via password)."
  def sign_with_credential(user_id, password, data) do
    with cred when not is_nil(cred) <- get_signing_credential(user_id),
         {:ok, private_key} <-
           KeyOps.decrypt_private_key(cred.encrypted_private_key, cred.salt, password),
         algo when not is_nil(algo) <- PkiCrypto.Registry.get(cred.algorithm) do
      PkiCrypto.Algorithm.sign(algo, private_key, data)
    else
      nil -> {:error, :credential_not_found}
      {:error, reason} -> {:error, reason}
    end
  end

  # --- Private ---

  defp create_credential(user_id, credential_type, algorithm, password) do
    case KeyOps.generate_credential_keypair(algorithm, password) do
      {:ok, %{public_key: pub, encrypted_private_key: enc_priv, salt: salt}} ->
        %Credential{}
        |> Credential.changeset(%{
          user_id: user_id,
          credential_type: credential_type,
          algorithm: algorithm,
          public_key: pub,
          encrypted_private_key: enc_priv,
          salt: salt
        })
        |> Repo.insert()

      {:error, reason} ->
        {:error, reason}
    end
  end
end
