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

  def create_database(name, slug, email, opts \\ []) do
    schema_mode = Keyword.get(opts, :schema_mode, "schema")
    Provisioner.create_tenant(name, slug, email: email, schema_mode: schema_mode)
  end

  def activate(tenant_id) do
    Provisioner.activate_tenant(tenant_id)
  end

  def create_instances(tenant) do
    PkiPlatformEngine.EngineBootstrap.ensure_all_instances(tenant)
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

end
