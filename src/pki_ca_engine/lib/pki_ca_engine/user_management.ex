defmodule PkiCaEngine.UserManagement do
  @moduledoc """
  CRUD operations for CA users with role-based access control.

  Enforces least-privilege: each role maps to a fixed set of permissions.
  """

  import Ecto.Query

  alias PkiCaEngine.Repo
  alias PkiCaEngine.Schema.CaUser

  @role_permissions %{
    "ca_admin" => [:manage_ca_admins, :manage_auditors, :view_audit_log, :view_all],
    "key_manager" => [:manage_key_managers, :manage_keystores, :manage_keys, :manage_keypair_access],
    "ra_admin" => [:manage_ra_admins, :manage_ra_keypair_access],
    "auditor" => [:view_audit_log, :participate_ceremony]
  }

  @doc """
  Creates a user for the given CA instance.
  """
  @spec create_user(integer(), map()) :: {:ok, CaUser.t()} | {:error, Ecto.Changeset.t()}
  def create_user(ca_instance_id, attrs) do
    attrs = Map.put(attrs, :ca_instance_id, ca_instance_id)

    %CaUser{}
    |> CaUser.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Lists users for a CA instance. Accepts optional `role:` filter.
  """
  @spec list_users(integer(), keyword()) :: [CaUser.t()]
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
  @spec get_user(integer()) :: {:ok, CaUser.t()} | {:error, :not_found}
  def get_user(id) do
    case Repo.get(CaUser, id) do
      nil -> {:error, :not_found}
      user -> {:ok, user}
    end
  end

  @doc """
  Updates a user's display_name or status. Role and DID cannot be changed.
  """
  @spec update_user(integer(), map()) :: {:ok, CaUser.t()} | {:error, :not_found | Ecto.Changeset.t()}
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
  Soft-deletes a user by setting status to "suspended".
  """
  @spec delete_user(integer()) :: {:ok, CaUser.t()} | {:error, :not_found | Ecto.Changeset.t()}
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
