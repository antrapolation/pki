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

  def get_tenant_roles_any_status(user_profile_id, opts \\ []) do
    query = from r in UserTenantRole,
      where: r.user_profile_id == ^user_profile_id,
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

  @doc "List users for a specific tenant and portal with their roles."
  def list_users_for_portal(tenant_id, portal) do
    query = from r in UserTenantRole,
      where: r.tenant_id == ^tenant_id and r.portal == ^portal,
      join: u in UserProfile, on: u.id == r.user_profile_id,
      select: %{
        id: u.id,
        role_id: r.id,
        username: u.username,
        display_name: u.display_name,
        email: u.email,
        role: r.role,
        status: r.status,
        inserted_at: r.inserted_at
      },
      order_by: [asc: r.inserted_at]

    PlatformRepo.all(query)
  end

  @doc """
  Create a user for a portal with email invitation.
  Generates a temporary password, creates UserProfile + UserTenantRole,
  and sends an invitation email.
  """
  def create_user_for_portal(tenant_id, portal, attrs, opts \\ []) do
    email = attrs[:email] || attrs["email"]

    unless email && String.contains?(to_string(email), "@") do
      {:error, :email_required}
    else
      temp_password = generate_temp_password()
      expires_at = DateTime.add(DateTime.utc_now(), 24 * 3600, :second)
      role = attrs[:role] || attrs["role"]

      result = PlatformRepo.transaction(fn ->
        user_attrs = %{
          username: attrs[:username] || attrs["username"],
          display_name: attrs[:display_name] || attrs["display_name"],
          email: email,
          password: temp_password,
          must_change_password: true,
          credential_expires_at: expires_at
        }

        case create_user_profile(user_attrs) do
          {:ok, user} ->
            case assign_tenant_role(user.id, tenant_id, %{role: role, portal: portal}) do
              {:ok, %{id: nil}} ->
                PlatformRepo.rollback(:duplicate_role)

              {:ok, _role} ->
                user

              {:error, reason} ->
                PlatformRepo.rollback(reason)
            end

          {:error, changeset} ->
            PlatformRepo.rollback(changeset)
        end
      end)

      case result do
        {:ok, user} ->
          send_invitation_email(user, role, portal, temp_password, opts)
          {:ok, user}

        {:error, _} = err ->
          err
      end
    end
  end

  @doc "Suspend a user's tenant role (prevents login to that portal)."
  def suspend_user_role(role_id) do
    case PlatformRepo.get(UserTenantRole, role_id) do
      nil -> {:error, :not_found}
      role -> role |> UserTenantRole.changeset(%{status: "suspended"}) |> PlatformRepo.update()
    end
  end

  @doc "Activate a user's tenant role."
  def activate_user_role(role_id) do
    case PlatformRepo.get(UserTenantRole, role_id) do
      nil -> {:error, :not_found}
      role -> role |> UserTenantRole.changeset(%{status: "active"}) |> PlatformRepo.update()
    end
  end

  @doc "Delete a user's tenant role (removes access to that portal for that tenant)."
  def delete_user_role(role_id) do
    case PlatformRepo.get(UserTenantRole, role_id) do
      nil -> {:error, :not_found}
      role -> PlatformRepo.delete(role)
    end
  end

  @doc "Reset a user's password and send new credentials via email."
  def reset_user_password(user_profile_id, portal, opts \\ []) do
    temp_password = generate_temp_password()
    expires_at = DateTime.add(DateTime.utc_now(), 24 * 3600, :second)

    case PlatformRepo.get(UserProfile, user_profile_id) do
      nil -> {:error, :not_found}
      user ->
        changeset = user
          |> UserProfile.password_changeset(%{password: temp_password, must_change_password: true})
          |> Ecto.Changeset.put_change(:credential_expires_at, expires_at)

        case PlatformRepo.update(changeset) do
          {:ok, updated} ->
            role_label = Keyword.get(opts, :role_label, portal)
            send_password_reset_email(updated, role_label, portal, temp_password, opts)
            {:ok, updated}

          {:error, _} = err -> err
        end
    end
  end

  @doc "Get a user profile by ID."
  def get_user_profile(id) do
    case PlatformRepo.get(UserProfile, id) do
      nil -> {:error, :not_found}
      user -> {:ok, user}
    end
  end

  defp generate_temp_password do
    :crypto.strong_rand_bytes(12) |> Base.encode64(padding: false) |> binary_part(0, 16)
  end

  defp send_invitation_email(user, role, portal, password, opts) do
    portal_url = Keyword.get(opts, :portal_url, "")
    tenant_name = Keyword.get(opts, :tenant_name, "")
    role_label = format_role_label(role, portal)

    html = PkiPlatformEngine.EmailTemplates.user_invitation(tenant_name, role_label, portal_url, user.username, password)
    PkiPlatformEngine.Mailer.send_email(user.email, "You've been invited to #{tenant_name} - #{role_label}", html)
  end

  defp send_password_reset_email(user, role_label, _portal, password, opts) do
    portal_url = Keyword.get(opts, :portal_url, "")
    tenant_name = Keyword.get(opts, :tenant_name, "")

    html = PkiPlatformEngine.EmailTemplates.single_admin_credential(tenant_name, role_label, portal_url, user.username, password)
    PkiPlatformEngine.Mailer.send_email(user.email, "Your password has been reset - #{tenant_name}", html)
  end

  @doc "Format a role string into a human-readable label."
  def format_role_label(role, portal) do
    case {portal, role} do
      {"ca", "ca_admin"} -> "CA Administrator"
      {"ca", "key_manager"} -> "Key Manager"
      {"ca", "auditor"} -> "Auditor"
      {"ra", "ra_admin"} -> "RA Administrator"
      {"ra", "ra_officer"} -> "RA Officer"
      {"ra", "auditor"} -> "Auditor"
      {_, role} -> role
    end
  end
end
