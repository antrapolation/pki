defmodule PkiPlatformEngine.AdminManagement do
  alias PkiPlatformEngine.PlatformRepo
  alias PkiPlatformEngine.PlatformAdmin

  import Ecto.Query

  def needs_setup? do
    PlatformRepo.aggregate(PlatformAdmin, :count) == 0
  end

  def register_admin(attrs) do
    %PlatformAdmin{}
    |> PlatformAdmin.registration_changeset(attrs)
    |> PlatformRepo.insert()
  end

  def authenticate(username, password) do
    admin =
      PlatformRepo.one(
        from(a in PlatformAdmin,
          where: a.username == ^username and a.status == "active"
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
    case PlatformRepo.one(from(a in PlatformAdmin, where: a.username == ^username and a.status == "active")) do
      nil -> {:error, :not_found}
      admin -> {:ok, admin}
    end
  end

  def reset_admin_password(admin_id, new_password) do
    case PlatformRepo.get(PlatformAdmin, admin_id) do
      nil ->
        {:error, :not_found}

      admin ->
        admin
        |> PlatformAdmin.password_changeset(%{password: new_password})
        |> PlatformRepo.update()
    end
  end

  def list_admins do
    PlatformRepo.all(from(a in PlatformAdmin, order_by: [asc: a.inserted_at]))
  end

  def get_admin(id) do
    PlatformRepo.get(PlatformAdmin, id)
  end

  def update_admin_profile(%PlatformAdmin{} = admin, attrs) do
    allowed = Map.take(attrs, [:display_name, :email, "display_name", "email"])

    admin
    |> PlatformAdmin.profile_changeset(allowed)
    |> PlatformRepo.update()
  end

  def change_admin_password(%PlatformAdmin{} = admin, current_password, new_password) do
    if Argon2.verify_pass(current_password, admin.password_hash) do
      admin
      |> PlatformAdmin.password_changeset(%{password: new_password})
      |> PlatformRepo.update()
    else
      {:error, :invalid_current_password}
    end
  end

  def update_admin(%PlatformAdmin{} = admin, attrs) do
    admin
    |> PlatformAdmin.changeset(attrs)
    |> PlatformRepo.update()
  end

  def suspend_admin(%PlatformAdmin{} = admin) do
    PlatformRepo.transaction(fn ->
      active_count =
        PlatformRepo.aggregate(
          from(a in PlatformAdmin, where: a.status == "active"),
          :count
        )

      if active_count <= 1 do
        PlatformRepo.rollback(:last_active_admin)
      else
        admin
        |> PlatformAdmin.changeset(%{status: "suspended"})
        |> PlatformRepo.update!()
      end
    end)
  end

  def activate_admin(%PlatformAdmin{} = admin) do
    update_admin(admin, %{status: "active"})
  end

  def delete_admin(%PlatformAdmin{} = admin) do
    PlatformRepo.transaction(fn ->
      active_count =
        PlatformRepo.aggregate(
          from(a in PlatformAdmin, where: a.status == "active"),
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
