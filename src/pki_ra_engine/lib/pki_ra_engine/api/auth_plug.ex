defmodule PkiRaEngine.Api.AuthPlug do
  @moduledoc """
  Plug that authenticates requests via the Authorization header.

  Accepts two forms of Bearer token:
  1. **Internal API secret** — used by the RA Portal for portal-to-engine calls.
     Configured via `config :pki_ra_engine, :internal_api_secret`.
  2. **API key** — used by external clients (base64-encoded raw key).
     Verified via `ApiKeyManagement.verify_key/2`.

  The internal secret is checked first for efficiency. If neither matches,
  the request is rejected with 401.
  """

  import Plug.Conn
  require Logger

  def init(opts), do: opts

  def call(conn, _opts) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] ->
        tenant_id = List.first(Plug.Conn.get_req_header(conn, "x-tenant-id"))

        # Validate tenant exists before proceeding (prevents crashes downstream)
        # nil tenant is allowed (falls back to default repo for single-tenant/bootstrap)
        case validate_tenant(tenant_id) do
          {:error, :unknown_tenant} ->
            conn
            |> put_resp_content_type("application/json")
            |> send_resp(422, Jason.encode!(%{error: "unknown_tenant", tenant_id: tenant_id}))
            |> halt()

          :ok ->
            authenticate(conn, token, tenant_id)
        end

      _ ->
        unauthorized(conn)
    end
  end

  defp authenticate(conn, token, tenant_id) do
    cond do
      valid_internal_secret?(token) ->
        Logger.metadata(engine: "ra", auth_type: :internal, tenant_id: tenant_id)

        conn
        |> assign(:auth_type, :internal)
        |> assign(:tenant_id, tenant_id)

      true ->
        case PkiRaEngine.ApiKeyManagement.verify_key(tenant_id, token) do
          {:ok, api_key} ->
            Logger.metadata(
              engine: "ra",
              auth_type: :api_key,
              tenant_id: tenant_id,
              api_key_id: api_key.id,
              ra_user_id: api_key.ra_user_id
            )

            conn
            |> assign(:auth_type, :api_key)
            |> assign(:current_api_key, api_key)
            |> assign(:tenant_id, tenant_id)

          _ ->
            unauthorized(conn)
        end
    end
  end

  defp validate_tenant(nil), do: :ok
  defp validate_tenant(""), do: :ok
  defp validate_tenant(tenant_id) do
    case PkiRaEngine.TenantRepo.ra_repo_safe(tenant_id) do
      {:ok, _repo} -> :ok
      {:error, :tenant_not_found} -> {:error, :unknown_tenant}
    end
  end

  defp valid_internal_secret?(token) do
    expected = Application.get_env(:pki_ra_engine, :internal_api_secret)
    is_binary(expected) and expected != "" and Plug.Crypto.secure_compare(token, expected)
  end

  defp unauthorized(conn) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(401, Jason.encode!(%{error: "unauthorized"}))
    |> halt()
  end
end
