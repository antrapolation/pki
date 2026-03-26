defmodule PkiTenancy.ResolverTest do
  use ExUnit.Case, async: false

  alias PkiTenancy.{PlatformRepo, Resolver, Tenant}

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(PlatformRepo)
    :ok
  end

  # Insert a Tenant record directly without using the Provisioner (avoids real DB creation).
  defp insert_tenant(attrs) do
    defaults = %{
      name: "Test Tenant #{System.unique_integer([:positive])}",
      slug: "test-slug-#{System.unique_integer([:positive])}",
      database_name: "pki_tenant_fake_#{System.unique_integer([:positive])}",
      status: "active"
    }

    merged = Map.merge(defaults, attrs)

    %Tenant{}
    |> Tenant.changeset(merged)
    |> PlatformRepo.insert!()
  end

  describe "resolve_from_slug/1" do
    test "returns {:ok, tenant} for an active tenant with matching slug" do
      tenant = insert_tenant(%{name: "Acme Corp", slug: "acme-corp"})

      assert {:ok, found} = Resolver.resolve_from_slug("acme-corp")
      assert found.id == tenant.id
      assert found.slug == "acme-corp"
    end

    test "returns {:error, :tenant_not_found} for a nonexistent slug" do
      assert {:error, :tenant_not_found} = Resolver.resolve_from_slug("nonexistent")
    end

    test "returns {:error, :tenant_not_found} for a suspended tenant" do
      insert_tenant(%{name: "Suspended Corp", slug: "suspended-corp", status: "suspended"})

      # Suspended tenants are not resolvable by slug (slug lookup requires status: "active")
      assert {:error, :tenant_not_found} = Resolver.resolve_from_slug("suspended-corp")
    end
  end

  describe "resolve_from_id/1" do
    test "returns {:ok, tenant} for a valid active tenant ID" do
      tenant = insert_tenant(%{name: "ID Lookup Corp", slug: "id-lookup-corp"})

      assert {:ok, found} = Resolver.resolve_from_id(tenant.id)
      assert found.id == tenant.id
    end

    test "returns {:error, :tenant_suspended} for a suspended tenant" do
      tenant = insert_tenant(%{
        name: "Suspended ID Corp",
        slug: "suspended-id-corp",
        status: "suspended"
      })

      assert {:error, :tenant_suspended} = Resolver.resolve_from_id(tenant.id)
    end

    test "returns {:error, :tenant_not_found} for a nonexistent ID" do
      assert {:error, :tenant_not_found} = Resolver.resolve_from_id(Uniq.UUID.uuid7())
    end
  end

  describe "resolve_from_subdomain/1" do
    test "resolves tenant from a valid subdomain" do
      tenant = insert_tenant(%{name: "Subdomain Corp", slug: "myorg"})

      assert {:ok, found} = Resolver.resolve_from_subdomain("myorg.ca.example.com")
      assert found.id == tenant.id
    end

    test "returns {:error, :tenant_not_found} for a reserved subdomain (localhost)" do
      assert {:error, :tenant_not_found} = Resolver.resolve_from_subdomain("localhost")
    end

    test "returns {:error, :tenant_not_found} for reserved subdomains (www, ca, ra, api, ocsp)" do
      for reserved <- ["www.example.com", "ca.example.com", "ra.example.com", "api.example.com", "ocsp.example.com"] do
        assert {:error, :tenant_not_found} = Resolver.resolve_from_subdomain(reserved),
               "Expected #{reserved} to return :tenant_not_found"
      end
    end

    test "returns {:error, :tenant_not_found} when subdomain tenant does not exist" do
      assert {:error, :tenant_not_found} = Resolver.resolve_from_subdomain("unknown.ca.example.com")
    end
  end

  describe "resolve_from_session/1" do
    test "returns {:ok, tenant} when session has :tenant_id atom key" do
      tenant = insert_tenant(%{name: "Session Corp", slug: "session-corp"})

      assert {:ok, found} = Resolver.resolve_from_session(%{tenant_id: tenant.id})
      assert found.id == tenant.id
    end

    test "returns {:ok, tenant} when session has \"tenant_id\" string key" do
      tenant = insert_tenant(%{name: "Session String Corp", slug: "session-string-corp"})

      assert {:ok, found} = Resolver.resolve_from_session(%{"tenant_id" => tenant.id})
      assert found.id == tenant.id
    end

    test "returns {:error, :tenant_not_found} for an empty session" do
      assert {:error, :tenant_not_found} = Resolver.resolve_from_session(%{})
    end

    test "returns {:error, :tenant_not_found} when session tenant_id does not exist" do
      assert {:error, :tenant_not_found} =
               Resolver.resolve_from_session(%{"tenant_id" => Uniq.UUID.uuid7()})
    end
  end
end
