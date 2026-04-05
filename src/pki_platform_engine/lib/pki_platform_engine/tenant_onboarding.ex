defmodule PkiPlatformEngine.TenantOnboarding do
  @moduledoc """
  Consolidates the full tenant provisioning chain:
  1. Create database + schemas + migrations
  2. Activate tenant (spawn repos, register in ETS)
  3. Create default CA and RA instances
  4. Create tenant_admin user in platform portal
  5. Send credentials email to tenant admin
  """

  alias PkiPlatformEngine.{Provisioner, PlatformAuth}
  require Logger

  def create_database(name, slug, email) do
    Provisioner.create_tenant(name, slug, email: email)
  end

  def activate(tenant_id) do
    Provisioner.activate_tenant(tenant_id)
  end

  def create_instances(tenant) do
    ca_errors = ensure_default_ca_instance(tenant)
    ra_errors = ensure_default_ra_instance(tenant)

    case ca_errors ++ ra_errors do
      [] -> :ok
      errors -> {:error, Enum.join(errors, "; ")}
    end
  end

  def create_tenant_admin(tenant) do
    username = "#{tenant.slug}-admin"
    portal_url = "https://#{System.get_env("PLATFORM_PORTAL_HOST", "platform.straptrust.com")}"

    PlatformAuth.create_user_for_portal(tenant.id, "platform", %{
      username: username,
      display_name: "#{tenant.name} Admin",
      email: tenant.email,
      role: "tenant_admin"
    }, portal_url: portal_url, tenant_name: tenant.name)
  end

  defp ensure_default_ca_instance(tenant) do
    case PkiCaEngine.CaInstanceManagement.list_hierarchy(tenant.id) do
      [] ->
        case PkiCaEngine.CaInstanceManagement.create_ca_instance(tenant.id, %{
               name: "#{tenant.name} Root CA",
               status: "active"
             }) do
          {:ok, _ca} -> []
          {:error, reason} ->
            Logger.error("[TenantOnboarding] CA instance creation failed: #{inspect(reason)}")
            ["CA instance creation failed"]
        end
      _instances -> []
    end
  rescue
    e ->
      Logger.error("[TenantOnboarding] CA instance creation failed: #{Exception.message(e)}")
      ["CA instance creation failed"]
  end

  defp ensure_default_ra_instance(tenant) do
    case PkiRaEngine.RaInstanceManagement.list_ra_instances(tenant.id) do
      [] ->
        case PkiRaEngine.RaInstanceManagement.create_ra_instance(tenant.id, %{
               name: "#{tenant.name} RA",
               status: "active"
             }) do
          {:ok, _ra} -> []
          {:error, reason} ->
            Logger.error("[TenantOnboarding] RA instance creation failed: #{inspect(reason)}")
            ["RA instance creation failed"]
        end
      _instances -> []
    end
  rescue
    e ->
      Logger.error("[TenantOnboarding] RA instance creation failed: #{Exception.message(e)}")
      ["RA instance creation failed"]
  end
end
