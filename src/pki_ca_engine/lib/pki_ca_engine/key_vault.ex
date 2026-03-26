defmodule PkiCaEngine.KeyVault do
  @moduledoc """
  Manages operational keypair registration, access grants, and activation.
  Uses the Keypair ACL for cryptographic access control.
  """

  alias PkiCaEngine.Repo
  alias PkiCaEngine.KeyVault.{ManagedKeypair, KeypairGrant}
  alias PkiCrypto.{Algorithm, Registry, Symmetric, Shamir}
  import Ecto.Query

  @doc """
  Register a new keypair with credential-owned protection.
  The keypair's activation password is encrypted with the ACL's KEM public key.
  """
  def register_keypair(ca_instance_id, name, algorithm, acl_kem_public_key, opts \\ []) do
    algo = Registry.get(algorithm)

    with {:ok, %{public_key: pub, private_key: priv}} <- Algorithm.generate_keypair(algo) do
      # Generate random password and encrypt private key
      random_password = :crypto.strong_rand_bytes(32)
      {:ok, encrypted_priv} = Symmetric.encrypt(priv, random_password)

      # Encrypt the random password with ACL's KEM public key
      kem_algo = Registry.get(Keyword.get(opts, :kem_algorithm, "ECDH-P256"))
      {:ok, {shared_secret, kem_ciphertext}} = Algorithm.kem_encapsulate(kem_algo, acl_kem_public_key)
      {:ok, encrypted_password} = Symmetric.encrypt(random_password <> kem_ciphertext, shared_secret)

      # Store the managed keypair
      %ManagedKeypair{}
      |> ManagedKeypair.changeset(%{
        ca_instance_id: ca_instance_id,
        name: name,
        algorithm: algorithm,
        protection_mode: "credential_own",
        public_key: pub,
        encrypted_private_key: encrypted_priv,
        encrypted_password: encrypted_password,
        status: "pending"
      })
      |> Repo.insert()
    end
  end

  @doc """
  Grant access to a keypair for a specific credential.
  Requires the ACL signing key (activated) to sign the grant envelope.
  """
  def grant_access(keypair_id, credential_id, acl_signing_key, acl_signing_algo \\ "ECC-P256") do
    now = DateTime.utc_now()

    # Construct grant envelope
    envelope_data =
      Jason.encode!(%{
        keypair_id: keypair_id,
        credential_id: credential_id,
        granted_at: DateTime.to_iso8601(now)
      })

    # Sign with ACL signing key
    algo = Registry.get(acl_signing_algo)
    {:ok, signature} = Algorithm.sign(algo, acl_signing_key, envelope_data)
    signed_envelope = envelope_data <> "||" <> Base.encode64(signature)

    %KeypairGrant{}
    |> KeypairGrant.changeset(%{
      managed_keypair_id: keypair_id,
      credential_id: credential_id,
      signed_envelope: signed_envelope,
      granted_at: now
    })
    |> Repo.insert()
  end

  @doc "Check if a credential has a valid (non-revoked) grant for a keypair."
  def has_grant?(keypair_id, credential_id) do
    Repo.exists?(
      from g in KeypairGrant,
        where:
          g.managed_keypair_id == ^keypair_id and
            g.credential_id == ^credential_id and
            is_nil(g.revoked_at)
    )
  end

  @doc "Get a managed keypair by ID."
  def get_keypair(id), do: Repo.get(ManagedKeypair, id)

  @doc "List managed keypairs for a CA instance."
  def list_keypairs(ca_instance_id) do
    Repo.all(
      from k in ManagedKeypair,
        where: k.ca_instance_id == ^ca_instance_id,
        order_by: [desc: k.inserted_at]
    )
  end

  @doc """
  Register a keypair with split-auth-token protection.
  The private key is encrypted with a random password; the password is split via Shamir(k, n).
  Returns `{:ok, keypair, shares}` where shares are raw binaries for custodians.
  """
  def register_keypair_split_auth(ca_instance_id, name, algorithm, threshold_k, threshold_n, opts \\ []) do
    algo = Registry.get(algorithm)

    with {:ok, %{public_key: pub, private_key: priv}} <- Algorithm.generate_keypair(algo) do
      # Generate random password and encrypt private key
      random_password = :crypto.strong_rand_bytes(32)
      {:ok, encrypted_priv} = Symmetric.encrypt(priv, random_password)

      # Split the password via Shamir
      {:ok, shares} = Shamir.split(random_password, threshold_k, threshold_n)

      # Store the managed keypair (encrypted password is NOT stored — only shares hold it)
      result =
        %ManagedKeypair{}
        |> ManagedKeypair.changeset(%{
          ca_instance_id: ca_instance_id,
          name: name,
          algorithm: algorithm,
          protection_mode: "split_auth_token",
          public_key: pub,
          encrypted_private_key: encrypted_priv,
          threshold_k: threshold_k,
          threshold_n: threshold_n,
          status: Keyword.get(opts, :status, "pending"),
          metadata: Keyword.get(opts, :metadata, %{})
        })
        |> Repo.insert()

      case result do
        {:ok, keypair} -> {:ok, keypair, shares}
        {:error, changeset} -> {:error, changeset}
      end
    end
  end

  @doc """
  Register a keypair with split-key protection.
  The PRIVATE KEY itself is split via Shamir(k, n) — it is NOT stored.
  Returns `{:ok, keypair, shares}` where shares are key fragments.
  """
  def register_keypair_split_key(ca_instance_id, name, algorithm, threshold_k, threshold_n, opts \\ []) do
    algo = Registry.get(algorithm)

    with {:ok, %{public_key: pub, private_key: priv}} <- Algorithm.generate_keypair(algo) do
      # Split the private key directly via Shamir
      {:ok, shares} = Shamir.split(priv, threshold_k, threshold_n)

      # Store the managed keypair — no encrypted_private_key
      result =
        %ManagedKeypair{}
        |> ManagedKeypair.changeset(%{
          ca_instance_id: ca_instance_id,
          name: name,
          algorithm: algorithm,
          protection_mode: "split_key",
          public_key: pub,
          threshold_k: threshold_k,
          threshold_n: threshold_n,
          status: Keyword.get(opts, :status, "pending"),
          metadata: Keyword.get(opts, :metadata, %{})
        })
        |> Repo.insert()

      case result do
        {:ok, keypair} -> {:ok, keypair, shares}
        {:error, changeset} -> {:error, changeset}
      end
    end
  end

  @doc """
  Activate a keypair from Shamir shares.
  For split_auth_token: recovers the password from shares, then decrypts the private key.
  For split_key: recovers the private key directly from shares.
  Returns `{:ok, private_key}`.
  """
  def activate_from_shares(keypair_id, shares) do
    case get_keypair(keypair_id) do
      nil ->
        {:error, :not_found}

      %{protection_mode: "split_auth_token"} = keypair ->
        with {:ok, password} <- Shamir.recover(shares),
             {:ok, private_key} <- Symmetric.decrypt(keypair.encrypted_private_key, password) do
          {:ok, private_key}
        end

      %{protection_mode: "split_key"} ->
        with {:ok, private_key} <- Shamir.recover(shares) do
          {:ok, private_key}
        end

      _other ->
        {:error, :invalid_protection_mode}
    end
  end

  @doc "Update keypair status."
  def update_status(keypair_id, status) do
    case Repo.get(ManagedKeypair, keypair_id) do
      nil ->
        {:error, :not_found}

      keypair ->
        keypair
        |> ManagedKeypair.changeset(%{status: status})
        |> Repo.update()
    end
  end

  @doc "Revoke a grant."
  def revoke_grant(keypair_id, credential_id) do
    case Repo.one(
           from g in KeypairGrant,
             where:
               g.managed_keypair_id == ^keypair_id and
                 g.credential_id == ^credential_id and
                 is_nil(g.revoked_at)
         ) do
      nil ->
        {:error, :grant_not_found}

      grant ->
        grant
        |> Ecto.Changeset.change(%{revoked_at: DateTime.utc_now()})
        |> Repo.update()
    end
  end
end
