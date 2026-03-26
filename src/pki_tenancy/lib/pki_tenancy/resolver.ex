defmodule PkiTenancy.Resolver do
  @moduledoc "Resolves tenant from request context."

  alias PkiTenancy.{PlatformRepo, Tenant}

  def resolve_from_subdomain(host) when is_binary(host) do
    case extract_slug(host) do
      nil -> {:error, :tenant_not_found}
      slug -> resolve_from_slug(slug)
    end
  end

  def resolve_from_header(conn) do
    case Plug.Conn.get_req_header(conn, "x-tenant-id") do
      [tenant_id] -> resolve_from_id(tenant_id)
      _ -> {:error, :tenant_not_found}
    end
  end

  def resolve_from_session(session) when is_map(session) do
    case Map.get(session, "tenant_id") || Map.get(session, :tenant_id) do
      nil -> {:error, :tenant_not_found}
      tenant_id -> resolve_from_id(tenant_id)
    end
  end

  def resolve_from_slug(slug) when is_binary(slug) do
    case PlatformRepo.get_by(Tenant, slug: slug, status: "active") do
      nil -> {:error, :tenant_not_found}
      tenant -> {:ok, tenant}
    end
  end

  def resolve_from_id(id) when is_binary(id) do
    case PlatformRepo.get(Tenant, id) do
      nil -> {:error, :tenant_not_found}
      %{status: "suspended"} -> {:error, :tenant_suspended}
      tenant -> {:ok, tenant}
    end
  end

  # Extract first subdomain segment: "acme.ca.example.com" → "acme"
  defp extract_slug(host) do
    case String.split(host, ".") do
      [slug | _rest] when byte_size(slug) > 0 ->
        if slug in ["www", "localhost", "ca", "ra", "api", "ocsp"], do: nil, else: slug

      _ ->
        nil
    end
  end
end
