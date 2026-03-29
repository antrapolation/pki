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

  def list_admins do
    PlatformRepo.all(from(a in PlatformAdmin, order_by: [asc: a.inserted_at]))
  end

  def get_admin(id) do
    PlatformRepo.get(PlatformAdmin, id)
  end

  def update_admin(%PlatformAdmin{} = admin, attrs) do
    admin
    |> PlatformAdmin.changeset(attrs)
    |> PlatformRepo.update()
  end

  def suspend_admin(%PlatformAdmin{} = admin) do
    active_count =
      PlatformRepo.aggregate(
        from(a in PlatformAdmin, where: a.status == "active"),
        :count
      )

    if active_count <= 1 do
      {:error, :last_active_admin}
    else
      update_admin(admin, %{status: "suspended"})
    end
  end

  def activate_admin(%PlatformAdmin{} = admin) do
    update_admin(admin, %{status: "active"})
  end

  def delete_admin(%PlatformAdmin{} = admin) do
    active_count =
      PlatformRepo.aggregate(
        from(a in PlatformAdmin, where: a.status == "active"),
        :count
      )

    if active_count <= 1 and admin.status == "active" do
      {:error, :last_active_admin}
    else
      PlatformRepo.delete(admin)
    end
  end

  def seed_from_env do
    username = Application.get_env(:pki_platform_portal, :admin_username)
    password = Application.get_env(:pki_platform_portal, :admin_password)

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
