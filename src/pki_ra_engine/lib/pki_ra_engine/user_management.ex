defmodule PkiRaEngine.UserManagement do
  @moduledoc """
  RA User Management — CRUD operations and role-based authorization.
  """

  import PkiRaEngine.QueryHelpers

  alias PkiRaEngine.Repo
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
  @spec register_user(map()) :: {:ok, RaUser.t()} | {:error, Ecto.Changeset.t() | :username_taken}
  def register_user(attrs) do
    password = attrs[:password] || attrs["password"]

    result =
      if password != nil do
        user_attrs = Map.drop(attrs, [:password, "password"])
        PkiRaEngine.CredentialManager.create_user_with_credentials(user_attrs, password)
      else
        case %RaUser{} |> RaUser.registration_changeset(attrs) |> Repo.insert() do
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
  @spec authenticate(String.t(), String.t()) :: {:ok, RaUser.t()} | {:error, :invalid_credentials}
  def authenticate(username, password) do
    import Ecto.Query
    case Repo.one(from u in RaUser, where: u.username == ^username and u.status == "active") do
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

  @doc "Returns true if no RA users exist."
  @spec needs_setup?() :: boolean()
  def needs_setup? do
    import Ecto.Query
    count = Repo.one(from u in RaUser, select: count(u.id))
    count == 0
  end

  @doc "Create a new RA user with credentials (password + dual keypairs)."
  @spec create_user_with_credentials(map(), String.t(), keyword()) :: {:ok, RaUser.t()} | {:error, term()}
  def create_user_with_credentials(attrs, password, opts \\ []) do
    PkiRaEngine.CredentialManager.create_user_with_credentials(attrs, password, opts)
  end

  @doc """
  Authenticate with credential verification (password + key ownership).
  Returns {:ok, user, session_info} or {:error, :invalid_credentials}.
  """
  @spec authenticate_with_credentials(String.t(), String.t()) :: {:ok, RaUser.t(), map()} | {:error, :invalid_credentials}
  def authenticate_with_credentials(username, password) do
    PkiRaEngine.CredentialManager.authenticate(username, password)
  end

  @doc "Create a new RA user (without password, for admin-created users)."
  @spec create_user(map()) :: {:ok, RaUser.t()} | {:error, Ecto.Changeset.t()}
  def create_user(attrs) do
    %RaUser{}
    |> RaUser.changeset(attrs)
    |> Repo.insert()
  end

  @doc "List users with optional keyword filters (:role, :status)."
  @spec list_users(keyword()) :: [RaUser.t()]
  def list_users(filters) do
    RaUser
    |> apply_eq_filters(filters)
    |> Repo.all()
  end

  @doc "Get a user by ID."
  @spec get_user(String.t()) :: {:ok, RaUser.t()} | {:error, :not_found}
  def get_user(id) do
    case Repo.get(RaUser, id) do
      nil -> {:error, :not_found}
      user -> {:ok, user}
    end
  end

  @doc "Update a user's display_name or status only."
  @spec update_user(String.t(), map()) :: {:ok, RaUser.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def update_user(id, attrs) do
    with {:ok, user} <- get_user(id) do
      allowed = Map.take(attrs, [:display_name, :status, "display_name", "status"])

      user
      |> RaUser.changeset(allowed)
      |> Repo.update()
    end
  end

  @doc "Soft-delete a user by setting status to suspended."
  @spec delete_user(String.t()) :: {:ok, RaUser.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def delete_user(id) do
    update_user(id, %{status: "suspended"})
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
