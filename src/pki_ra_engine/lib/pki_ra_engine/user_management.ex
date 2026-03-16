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

  @doc "Create a new RA user."
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
  @spec get_user(integer()) :: {:ok, RaUser.t()} | {:error, :not_found}
  def get_user(id) do
    case Repo.get(RaUser, id) do
      nil -> {:error, :not_found}
      user -> {:ok, user}
    end
  end

  @doc "Update a user's display_name or status only."
  @spec update_user(integer(), map()) :: {:ok, RaUser.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def update_user(id, attrs) do
    with {:ok, user} <- get_user(id) do
      allowed = Map.take(attrs, [:display_name, :status, "display_name", "status"])

      user
      |> RaUser.changeset(allowed)
      |> Repo.update()
    end
  end

  @doc "Soft-delete a user by setting status to suspended."
  @spec delete_user(integer()) :: {:ok, RaUser.t()} | {:error, :not_found | Ecto.Changeset.t()}
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
