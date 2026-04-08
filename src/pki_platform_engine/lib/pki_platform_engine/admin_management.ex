defmodule PkiPlatformEngine.AdminManagement do
  @moduledoc """
  Manages super_admin users via the unified user_profiles table.
  Super admins are identified by global_role == "super_admin".
  """
  alias PkiPlatformEngine.PlatformRepo
  alias PkiPlatformEngine.UserProfile

  import Ecto.Query

  @super_admin_query from(u in UserProfile, where: u.global_role == "super_admin")

  def needs_setup? do
    PlatformRepo.aggregate(@super_admin_query, :count) == 0
  end

  def register_admin(attrs) do
    attrs = Map.put(attrs, :global_role, "super_admin")

    %UserProfile{}
    |> UserProfile.registration_changeset(attrs)
    |> PlatformRepo.insert()
  end

  @doc "Creates an admin with a temp password and sends invitation email."
  def invite_admin(attrs) do
    temp_password = :crypto.strong_rand_bytes(18) |> Base.url_encode64(padding: false)
    expires_at = DateTime.add(DateTime.utc_now(), 24 * 3600, :second)

    invite_attrs = %{
      username: attrs[:username] || attrs["username"],
      display_name: attrs[:display_name] || attrs["display_name"],
      email: attrs[:email] || attrs["email"],
      password: temp_password,
      must_change_password: true,
      credential_expires_at: expires_at,
      global_role: "super_admin"
    }

    case %UserProfile{}
         |> UserProfile.registration_changeset(invite_attrs)
         |> PlatformRepo.insert() do
      {:ok, admin} ->
        send_admin_invitation(admin, temp_password)
        {:ok, admin}

      {:error, _} = err ->
        err
    end
  end

  defp send_admin_invitation(admin, temp_password) do
    portal_url = System.get_env("PLATFORM_PORTAL_URL", "http://localhost:4006")

    html = PkiPlatformEngine.EmailTemplates.single_admin_credential(
      "PQC PKI Platform",
      "Platform Administrator",
      portal_url,
      admin.username,
      temp_password
    )

    PkiPlatformEngine.Mailer.send_email(
      admin.email,
      "You've been invited as Platform Administrator",
      html
    )
  end

  def authenticate(username, password) do
    admin =
      PlatformRepo.one(
        from(u in UserProfile,
          where: u.username == ^username and u.status == "active" and u.global_role == "super_admin"
        )
      )

    case admin do
      nil -> {:error, :invalid_credentials}
      admin ->
        if Argon2.verify_pass(password, admin.password_hash) do
          {:ok, admin}
        else
          {:error, :invalid_credentials}
        end
    end
  end

  def get_admin_by_username(username) do
    case PlatformRepo.one(from(u in UserProfile, where: u.username == ^username and u.global_role == "super_admin" and u.status == "active")) do
      nil -> {:error, :not_found}
      admin -> {:ok, admin}
    end
  end

  def reset_admin_password(admin_id, new_password) do
    case PlatformRepo.get(UserProfile, admin_id) do
      nil ->
        {:error, :not_found}

      admin ->
        admin
        |> UserProfile.password_changeset(%{password: new_password})
        |> PlatformRepo.update()
    end
  end

  def list_admins do
    PlatformRepo.all(from(u in @super_admin_query, order_by: [asc: u.inserted_at]))
  end

  def get_admin(id) do
    PlatformRepo.get(UserProfile, id)
  end

  def update_admin_profile(%UserProfile{} = admin, attrs) do
    allowed = Map.take(attrs, [:display_name, :email, "display_name", "email"])

    admin
    |> UserProfile.changeset(allowed)
    |> PlatformRepo.update()
  end

  def change_admin_password(%UserProfile{} = admin, current_password, new_password) do
    if Argon2.verify_pass(current_password, admin.password_hash) do
      admin
      |> UserProfile.password_changeset(%{password: new_password})
      |> PlatformRepo.update()
    else
      {:error, :invalid_current_password}
    end
  end

  def update_admin(%UserProfile{} = admin, attrs) do
    admin
    |> UserProfile.changeset(attrs)
    |> PlatformRepo.update()
  end

  def suspend_admin(%UserProfile{} = admin) do
    result = PlatformRepo.transaction(fn ->
      active_count =
        PlatformRepo.aggregate(
          from(u in @super_admin_query, where: u.status == "active"),
          :count
        )

      if active_count <= 1 do
        PlatformRepo.rollback(:last_active_admin)
      else
        admin
        |> UserProfile.changeset(%{status: "suspended"})
        |> PlatformRepo.update!()
      end
    end)

    case result do
      {:ok, _suspended_admin} ->
        # Terminate active sessions for suspended admin
        try do
          PkiPlatformPortal.SessionStore.delete_by_user(admin.id)
        rescue
          _ -> :ok  # SessionStore may not be available in engine context
        end
        result

      _ ->
        result
    end
  end

  def activate_admin(%UserProfile{} = admin) do
    update_admin(admin, %{status: "active"})
  end

  def delete_admin(%UserProfile{} = admin) do
    PlatformRepo.transaction(fn ->
      active_count =
        PlatformRepo.aggregate(
          from(u in @super_admin_query, where: u.status == "active"),
          :count
        )

      if active_count <= 1 and admin.status == "active" do
        PlatformRepo.rollback(:last_active_admin)
      else
        PlatformRepo.delete!(admin)
      end
    end)
  end

  def seed_from_env do
    username = System.get_env("PLATFORM_ADMIN_USERNAME")
    password = System.get_env("PLATFORM_ADMIN_PASSWORD")

    if username && password && needs_setup?() do
      case register_admin(%{
             username: username,
             display_name: "Platform Admin",
             password: password
           }) do
        {:ok, _admin} ->
          require Logger
          Logger.warning("Seeded platform admin from env vars. This is deprecated — manage admins via the portal.")
        {:error, _} -> :ok
      end
    end
  end
end
