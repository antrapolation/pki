defmodule PkiCaEngine.CredentialManager do
  @moduledoc """
  Manages user credentials (dual signing + KEM keypairs).

  Every user in the system has two cryptographic credentials:
  - Signing credential: for digital signatures and attestations
  - KEM credential: for key encapsulation (encrypting secrets for the user)
  """

  alias PkiCaEngine.Repo
  alias PkiCaEngine.Schema.CaUser
  alias PkiCaEngine.CredentialManager.{Credential, KeyOps}
  alias PkiCrypto.{Attestation, Kdf}
  import Ecto.Query
  require Logger

  @doc """
  Create a user with dual credentials (signing + KEM keypairs).
  The private keys are encrypted with a key derived from the user's password.

  ## Options

    * `:signing_algorithm` - algorithm for signing keypair (default: "ECC-P256")
    * `:kem_algorithm` - algorithm for KEM keypair (default: "ECDH-P256")
    * `:admin_context` - `%{user_id: id, password: password}` of the creating admin.
      When provided, the admin's signing key attests the new user's public keys.
      When absent (bootstrap), the new user self-attests.
  """
  def create_user_with_credentials(ca_instance_id, user_attrs, password, opts \\ []) do
    signing_algo = Keyword.get(opts, :signing_algorithm, "ECC-P256")
    kem_algo = Keyword.get(opts, :kem_algorithm, "ECDH-P256")
    admin_context = Keyword.get(opts, :admin_context)

    Repo.transaction(fn ->
      # 1. Create the user record
      user_changeset =
        CaUser.registration_changeset(
          %CaUser{},
          Map.merge(user_attrs, %{
            ca_instance_id: ca_instance_id,
            password: password
          })
        )

      case Repo.insert(user_changeset) do
        {:ok, user} ->
          # 2. Generate signing credential
          case create_credential(user.id, "signing", signing_algo, password) do
            {:ok, signing_cred} ->
              # 3. Generate KEM credential
              case create_credential(user.id, "kem", kem_algo, password) do
                {:ok, kem_cred} ->
                  # 4. Attest both public keys
                  case attest_credentials(signing_cred, kem_cred, signing_algo, password, admin_context) do
                    :ok ->
                      Repo.preload(user, :credentials)

                    {:error, reason} ->
                      Repo.rollback({:attestation_failed, reason})
                  end

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
  Returns {:ok, user, session_key} or {:error, :invalid_credentials}.
  """
  def authenticate(username, password) do
    user =
      Repo.one(
        from u in CaUser,
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
            # Verify attestation certificate if present
            case verify_credential_attestation(signing_cred) do
              :ok ->
                # Generate session key for this login session
                session_salt = Kdf.generate_salt()

                case Kdf.derive_key(password, session_salt) do
                  {:ok, session_key} ->
                    {:ok, user, %{session_key: session_key, session_salt: session_salt}}

                  {:error, _} ->
                    {:error, :invalid_credentials}
                end

              {:error, _} ->
                {:error, :invalid_credentials}
            end
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

  # Attest both credentials' public keys.
  # Bootstrap (no admin_context): self-attest using the new user's own signing key.
  # Normal (admin_context provided): admin's signing key attests the new user's keys.
  defp attest_credentials(signing_cred, kem_cred, signing_algo, password, nil) do
    # Bootstrap / self-attestation: decrypt the new user's own signing key
    # The attester is the user themselves — store their own public key as attested_by_key
    with {:ok, signing_key} <- KeyOps.decrypt_private_key(signing_cred.encrypted_private_key, signing_cred.salt, password),
         {:ok, signing_cert} <- Attestation.attest(signing_key, signing_algo, signing_cred.public_key),
         {:ok, kem_cert} <- Attestation.attest(signing_key, signing_algo, kem_cred.public_key),
         {:ok, _} <- update_certificate(signing_cred, signing_cert, signing_cred.public_key),
         {:ok, _} <- update_certificate(kem_cred, kem_cert, signing_cred.public_key) do
      :ok
    else
      {:error, reason} -> {:error, reason}
      other -> {:error, {:unexpected_attestation_result, other}}
    end
  end

  defp attest_credentials(signing_cred, kem_cred, _signing_algo, _password, %{user_id: admin_id, password: admin_password}) do
    # Admin-attested: look up admin's signing credential and decrypt with their password
    admin_signing = get_signing_credential(admin_id)

    if is_nil(admin_signing) do
      {:error, :admin_signing_credential_not_found}
    else
      with {:ok, admin_key} <- KeyOps.decrypt_private_key(admin_signing.encrypted_private_key, admin_signing.salt, admin_password),
           {:ok, signing_cert} <- Attestation.attest(admin_key, admin_signing.algorithm, signing_cred.public_key),
           {:ok, kem_cert} <- Attestation.attest(admin_key, admin_signing.algorithm, kem_cred.public_key),
           {:ok, _} <- update_certificate(signing_cred, signing_cert, admin_signing.public_key),
           {:ok, _} <- update_certificate(kem_cred, kem_cert, admin_signing.public_key) do
        :ok
      else
        {:error, reason} -> {:error, reason}
        other -> {:error, {:unexpected_attestation_result, other}}
      end
    end
  end

  defp verify_credential_attestation(%Credential{certificate: nil, user_id: uid}) do
    Logger.warning("Credential for user #{uid} has no attestation certificate")
    :ok
  end

  defp verify_credential_attestation(%Credential{attested_by_key: nil, id: id}) do
    Logger.warning("Credential #{id} missing attested_by_key, skipping verification")
    :ok
  end

  defp verify_credential_attestation(%Credential{} = cred) do
    case Attestation.verify_attestation(cred.attested_by_key, cred.algorithm, cred.certificate, cred.public_key) do
      :ok ->
        :ok

      {:error, :invalid_signature} ->
        Logger.error("Attestation verification FAILED for credential #{cred.id}")
        {:error, :invalid_signature}

      other ->
        Logger.error("Unexpected attestation result for credential #{cred.id}: #{inspect(other)}")
        {:error, :attestation_error}
    end
  rescue
    e ->
      Logger.error("Attestation verification crashed for credential #{cred.id}: #{Exception.message(e)}")
      {:error, :attestation_error}
  end

  defp update_certificate(credential, certificate, attester_public_key) do
    credential
    |> Credential.changeset(%{certificate: certificate, attested_by_key: attester_public_key})
    |> Repo.update()
  end

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
