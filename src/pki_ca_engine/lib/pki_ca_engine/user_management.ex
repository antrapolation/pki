defmodule PkiCaEngine.UserManagement do
  @moduledoc """
  CRUD operations for CA users with role-based access control.

  Enforces least-privilege: each role maps to a fixed set of permissions.
  """

  import Ecto.Query

  alias PkiCaEngine.Repo
  alias PkiCaEngine.Schema.CaUser
  alias PkiCaEngine.CredentialManager
  alias PkiCaEngine.Bootstrap

  @role_permissions %{
    "ca_admin" => [:manage_ca_admins, :manage_auditors, :view_audit_log, :view_all],
    "key_manager" => [:manage_key_managers, :manage_keystores, :manage_keys, :manage_keypair_access],
    "ra_admin" => [:manage_ra_admins, :manage_ra_keypair_access],
    "auditor" => [:view_audit_log, :participate_ceremony]
  }

  @doc """
  Registers a new user with username and password (bootstrap flow).
  Also creates cryptographic credentials (signing + KEM keypairs) when a password is provided.
  """
  @spec register_user(String.t(), map()) :: {:ok, CaUser.t()} | {:error, Ecto.Changeset.t() | :setup_already_complete}
  def register_user(ca_instance_id, attrs) do
    password = attrs[:password] || attrs["password"]

    if needs_setup?(ca_instance_id) and password != nil do
      # Full bootstrap: admin + ACL + system keypairs
      user_attrs = Map.drop(attrs, [:password, "password", :ca_instance_id, "ca_instance_id"])

      case Bootstrap.setup_tenant(ca_instance_id, user_attrs, password) do
        {:ok, %{admin: admin}} -> {:ok, admin}
        {:error, reason} -> {:error, reason}
      end
    else
      Repo.transaction(fn ->
        # Re-check inside transaction to prevent TOCTOU race
        count = Repo.one(from u in CaUser, where: u.ca_instance_id == ^ca_instance_id, select: count(u.id))

        if count > 0 do
          Repo.rollback(:setup_already_complete)
        else
          # Legacy flow: create user without credentials
          full_attrs = Map.put(attrs, :ca_instance_id, ca_instance_id)

          case %CaUser{} |> CaUser.registration_changeset(full_attrs) |> Repo.insert() do
            {:ok, user} -> user
            {:error, changeset} -> Repo.rollback(changeset)
          end
        end
      end)
    end
  end

  @doc """
  Authenticates a user by username and password.
  Returns the user if credentials are valid.
  """
  @spec authenticate(String.t(), String.t()) :: {:ok, CaUser.t()} | {:error, :invalid_credentials}
  def authenticate(username, password) do
    case Repo.one(from u in CaUser, where: u.username == ^username and u.status == "active") do
      nil ->
        Argon2.no_user_verify()
        {:error, :invalid_credentials}

      user ->
        if Argon2.verify_pass(password, user.password_hash) do
          {:ok, user}
        else
          {:error, :invalid_credentials}
        end
    end
  end

  @doc """
  Authenticates a user with credentials, returning session info.
  Delegates to CredentialManager for full credential-aware authentication.
  Returns {:ok, user, session_info} on success.

  Falls back to password-only authentication if the user has no credentials.
  """
  @spec authenticate_with_credentials(String.t(), String.t()) ::
          {:ok, CaUser.t(), map()} | {:error, :invalid_credentials}
  def authenticate_with_credentials(username, password) do
    case CredentialManager.authenticate(username, password) do
      {:ok, user, session_info} ->
        {:ok, user, session_info}

      {:error, :invalid_credentials} ->
        # Fall back to password-only auth for users without credentials
        case authenticate(username, password) do
          {:ok, user} -> {:ok, user, %{}}
          error -> error
        end
    end
  end

  @doc """
  Creates a user with cryptographic credentials (signing + KEM keypairs).
  Delegates to CredentialManager.create_user_with_credentials/4.
  """
  @spec create_user_with_credentials(String.t(), map(), String.t(), keyword()) ::
          {:ok, CaUser.t()} | {:error, term()}
  def create_user_with_credentials(ca_instance_id, attrs, password, opts \\ []) do
    CredentialManager.create_user_with_credentials(ca_instance_id, attrs, password, opts)
  end

  @doc """
  Returns true if no users exist for the given CA instance.
  Used to determine if bootstrap setup is needed.
  """
  @spec needs_setup?(String.t()) :: boolean()
  def needs_setup?(ca_instance_id) do
    count = Repo.one(from u in CaUser, where: u.ca_instance_id == ^ca_instance_id, select: count(u.id))
    count == 0
  end

  @doc """
  Creates a user for the given CA instance (without password, legacy).
  """
  @spec create_user(String.t(), map()) :: {:ok, CaUser.t()} | {:error, Ecto.Changeset.t()}
  def create_user(ca_instance_id, attrs) do
    attrs = Map.put(attrs, :ca_instance_id, ca_instance_id)

    %CaUser{}
    |> CaUser.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Lists users for a CA instance. Accepts optional `role:` filter.
  """
  @spec list_users(String.t(), keyword()) :: [CaUser.t()]
  def list_users(ca_instance_id, opts \\ []) do
    query = from(u in CaUser, where: u.ca_instance_id == ^ca_instance_id)

    query =
      case Keyword.get(opts, :role) do
        nil -> query
        role -> from(u in query, where: u.role == ^role)
      end

    Repo.all(query)
  end

  @doc """
  Gets a user by ID.
  """
  @spec get_user(String.t()) :: {:ok, CaUser.t()} | {:error, :not_found}
  def get_user(id) do
    case Repo.get(CaUser, id) do
      nil -> {:error, :not_found}
      user -> {:ok, user}
    end
  end

  @doc """
  Updates a user's display_name or status. Role cannot be changed.
  """
  @spec update_user(String.t(), map()) :: {:ok, CaUser.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def update_user(id, attrs) do
    case Repo.get(CaUser, id) do
      nil ->
        {:error, :not_found}

      user ->
        user
        |> CaUser.update_changeset(attrs)
        |> Repo.update()
    end
  end

  @doc """
  Updates a user's password and optionally clears must_change_password.
  """
  @spec update_user_password(CaUser.t(), map()) :: {:ok, CaUser.t()} | {:error, Ecto.Changeset.t()}
  def update_user_password(%CaUser{} = user, attrs) do
    user
    |> CaUser.password_changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Soft-deletes a user by setting status to "suspended".
  """
  @spec delete_user(String.t()) :: {:ok, CaUser.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def delete_user(id) do
    update_user(id, %{status: "suspended"})
  end

  @doc """
  Checks if a user has a specific permission based on their role.

  Returns `:ok` if authorized, `{:error, :unauthorized}` otherwise.
  Suspended users are always unauthorized.
  """
  @spec authorize(CaUser.t(), atom()) :: :ok | {:error, :unauthorized}
  def authorize(%CaUser{status: "suspended"}, _permission), do: {:error, :unauthorized}

  def authorize(%CaUser{role: role}, permission) do
    permissions = Map.get(@role_permissions, role, [])

    if permission in permissions do
      :ok
    else
      {:error, :unauthorized}
    end
  end
end
