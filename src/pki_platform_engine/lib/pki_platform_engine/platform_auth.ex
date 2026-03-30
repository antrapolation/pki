defmodule PkiPlatformEngine.PlatformAuth do
  import Ecto.Query
  alias PkiPlatformEngine.{PlatformRepo, UserProfile, UserTenantRole}

  def authenticate(username, password) do
    case PlatformRepo.one(from u in UserProfile, where: u.username == ^username and u.status == "active") do
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

  def get_tenant_roles(user_profile_id, opts \\ []) do
    query = from r in UserTenantRole,
      where: r.user_profile_id == ^user_profile_id and r.status == "active",
      preload: [:tenant]

    query = case Keyword.get(opts, :portal) do
      nil -> query
      portal -> from r in query, where: r.portal == ^portal
    end

    PlatformRepo.all(query)
  end

  def authenticate_for_portal(username, password, portal) do
    with {:ok, user} <- authenticate(username, password) do
      case get_tenant_roles(user.id, portal: portal) do
        [] -> {:error, :no_tenant_assigned}
        [role | _] -> {:ok, user, role}
      end
    end
  end

  def create_user_profile(attrs) do
    %UserProfile{}
    |> UserProfile.registration_changeset(attrs)
    |> PlatformRepo.insert()
  end

  def find_or_create_user_profile(attrs) do
    username = attrs[:username] || attrs["username"]
    case PlatformRepo.get_by(UserProfile, username: username) do
      nil -> create_user_profile(attrs)
      existing -> {:ok, existing}
    end
  end

  def assign_tenant_role(user_profile_id, tenant_id, attrs) do
    full_attrs = attrs
      |> Map.put(:user_profile_id, user_profile_id)
      |> Map.put(:tenant_id, tenant_id)

    %UserTenantRole{}
    |> UserTenantRole.changeset(full_attrs)
    |> PlatformRepo.insert(on_conflict: :nothing)
  end

  def reset_password(user_profile_id, new_password, opts \\ []) do
    case PlatformRepo.get(UserProfile, user_profile_id) do
      nil -> {:error, :not_found}
      user ->
        user
        |> UserProfile.password_changeset(%{
          password: new_password,
          must_change_password: Keyword.get(opts, :must_change_password, true)
        })
        |> PlatformRepo.update()
    end
  end

  def reactivate(user_profile_id) do
    case PlatformRepo.get(UserProfile, user_profile_id) do
      nil -> {:error, :not_found}
      user -> user |> UserProfile.changeset(%{status: "active"}) |> PlatformRepo.update()
    end
  end

  def get_by_username(username) do
    case PlatformRepo.get_by(UserProfile, username: username) do
      nil -> {:error, :not_found}
      user -> {:ok, user}
    end
  end
end
