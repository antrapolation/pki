defmodule PkiRaEngine.UserManagement do
  @moduledoc """
  RA User Management — CRUD operations and role-based authorization.
  """

  import PkiRaEngine.QueryHelpers

  alias PkiRaEngine.TenantRepo
  alias PkiRaEngine.Schema.RaUser

  @permissions %{
    "ra_admin" => [
      :manage_ra_admins,
      :manage_ra_officers,
      :manage_cert_profiles,
      :manage_service_configs,
      :manage_api_keys
    ],
    "ra_officer" => [:process_csrs, :view_csrs],
    "auditor" => [:view_audit_log]
  }

  @doc "Register a new RA user with username and password. Creates cryptographic credentials when a password is provided."
  @spec register_user(String.t(), map()) :: {:ok, RaUser.t()} | {:error, Ecto.Changeset.t() | :username_taken}
  def register_user(tenant_id, attrs) do
    repo = TenantRepo.ra_repo(tenant_id)
    password = attrs[:password] || attrs["password"]

    result =
      if password != nil do
        user_attrs = Map.drop(attrs, [:password, "password"])
        PkiRaEngine.CredentialManager.create_user_with_credentials(tenant_id, user_attrs, password)
      else
        case %RaUser{} |> RaUser.registration_changeset(attrs) |> repo.insert() do
          {:ok, user} -> {:ok, user}
          {:error, changeset} -> {:error, changeset}
        end
      end

    case result do
      {:ok, user} -> {:ok, user}
      {:error, %Ecto.Changeset{} = changeset} ->
        if username_taken?(changeset) do
          {:error, :username_taken}
        else
          {:error, changeset}
        end
      {:error, reason} -> {:error, reason}
    end
  end

  defp username_taken?(%Ecto.Changeset{errors: errors}) do
    Enum.any?(errors, fn
      {:username, {_, [constraint: :unique, constraint_name: _]}} -> true
      _ -> false
    end)
  end

  @doc "Authenticate a user by username and password."
  @spec authenticate(String.t(), String.t(), String.t()) :: {:ok, RaUser.t()} | {:error, :invalid_credentials}
  def authenticate(tenant_id, username, password) do
    import Ecto.Query
    repo = TenantRepo.ra_repo(tenant_id)

    case repo.one(from u in RaUser, where: u.username == ^username and u.status == "active") do
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

  def get_user_by_username(tenant_id, username) do
    import Ecto.Query
    repo = TenantRepo.ra_repo(tenant_id)

    users = repo.all(from u in RaUser,
      where: u.username == ^username and u.status == "active"
    )

    case users do
      [user] -> {:ok, user}
      [] -> {:error, :not_found}
      _multiple -> {:error, :ambiguous_username}
    end
  end

  @doc "Returns true if no RA admin users exist (optionally scoped to a tenant)."
  @spec needs_setup?(String.t() | nil) :: boolean()
  def needs_setup?(tenant_id \\ nil) do
    import Ecto.Query
    repo = TenantRepo.ra_repo(tenant_id)
    query = from(u in RaUser, where: u.role == "ra_admin")
    query = if tenant_id, do: from(u in query, where: u.tenant_id == ^tenant_id), else: query
    repo.aggregate(query, :count) == 0
  end

  @doc "Create a new RA user with credentials (password + dual keypairs)."
  @spec create_user_with_credentials(String.t(), map(), String.t(), keyword()) :: {:ok, RaUser.t()} | {:error, term()}
  def create_user_with_credentials(tenant_id, attrs, password, opts \\ []) do
    PkiRaEngine.CredentialManager.create_user_with_credentials(tenant_id, attrs, password, opts)
  end

  @doc """
  Authenticate with credential verification (password + key ownership).
  Returns {:ok, user, session_info} or {:error, :invalid_credentials}.
  """
  @spec authenticate_with_credentials(String.t(), String.t(), String.t()) :: {:ok, RaUser.t(), map()} | {:error, :invalid_credentials}
  def authenticate_with_credentials(tenant_id, username, password) do
    PkiRaEngine.CredentialManager.authenticate(tenant_id, username, password)
  end

  @doc "Create a new RA user (without password, for admin-created users)."
  @spec create_user(String.t(), map()) :: {:ok, RaUser.t()} | {:error, Ecto.Changeset.t()}
  def create_user(tenant_id, attrs) do
    repo = TenantRepo.ra_repo(tenant_id)

    %RaUser{}
    |> RaUser.changeset(attrs)
    |> repo.insert()
  end

  @doc "List users with optional keyword filters (:role, :status, :tenant_id)."
  @spec list_users(String.t(), keyword()) :: [RaUser.t()]
  def list_users(tenant_id, filters) do
    import Ecto.Query
    repo = TenantRepo.ra_repo(tenant_id)

    query =
      RaUser
      |> apply_eq_filters(Keyword.delete(filters, :tenant_id))

    query =
      case Keyword.get(filters, :tenant_id) do
        nil -> query
        tid -> from(u in query, where: u.tenant_id == ^tid)
      end

    repo.all(query)
  end

  @doc "Get a user by ID."
  @spec get_user(String.t(), String.t()) :: {:ok, RaUser.t()} | {:error, :not_found}
  def get_user(tenant_id, id) do
    repo = TenantRepo.ra_repo(tenant_id)

    case repo.get(RaUser, id) do
      nil -> {:error, :not_found}
      user -> {:ok, user}
    end
  end

  @doc "Update a user's display_name or status only."
  @spec update_user(String.t(), String.t(), map()) :: {:ok, RaUser.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def update_user(tenant_id, id, attrs) do
    repo = TenantRepo.ra_repo(tenant_id)

    with {:ok, user} <- get_user(tenant_id, id) do
      allowed = Map.take(attrs, [:display_name, :status, "display_name", "status"])

      user
      |> RaUser.changeset(allowed)
      |> repo.update()
    end
  end

  @doc "Updates a user's display_name and/or email (self-service profile edit)."
  @spec update_user_profile(String.t(), String.t(), map()) :: {:ok, RaUser.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def update_user_profile(tenant_id, user_id, attrs) do
    repo = TenantRepo.ra_repo(tenant_id)
    case repo.get(RaUser, user_id) do
      nil ->
        {:error, :not_found}

      user ->
        allowed = Map.take(attrs, [:display_name, :email, "display_name", "email"])
        user |> RaUser.profile_changeset(allowed) |> repo.update()
    end
  end

  @doc "Verifies the current password and updates to a new one."
  @spec verify_and_change_password(String.t(), String.t(), String.t(), String.t()) ::
        {:ok, RaUser.t()} | {:error, :not_found | :invalid_current_password | Ecto.Changeset.t()}
  def verify_and_change_password(tenant_id, user_id, current_password, new_password) do
    repo = TenantRepo.ra_repo(tenant_id)
    case repo.get(RaUser, user_id) do
      nil ->
        {:error, :not_found}

      user ->
        if Argon2.verify_pass(current_password, user.password_hash) do
          user
          |> RaUser.password_changeset(%{password: new_password, must_change_password: false})
          |> repo.update()
        else
          {:error, :invalid_current_password}
        end
    end
  end

  @doc "Update a user's password and optionally clear must_change_password."
  @spec update_user_password(String.t(), RaUser.t(), map()) :: {:ok, RaUser.t()} | {:error, Ecto.Changeset.t()}
  def update_user_password(tenant_id, %RaUser{} = user, attrs) do
    repo = TenantRepo.ra_repo(tenant_id)

    user
    |> RaUser.password_changeset(attrs)
    |> repo.update()
  end

  @doc "Soft-delete a user by setting status to suspended."
  @spec delete_user(String.t(), String.t()) :: {:ok, RaUser.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def delete_user(tenant_id, id) do
    update_user(tenant_id, id, %{status: "suspended"})
  end

  @doc "Check if a role has a given permission."
  @spec authorize(String.t(), atom()) :: :ok | {:error, :unauthorized}
  def authorize(role, permission) do
    permissions = Map.get(@permissions, role, [])

    if permission in permissions do
      :ok
    else
      {:error, :unauthorized}
    end
  end

end
