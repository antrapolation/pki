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
            # Per-key rate limiting
            rate_limit = api_key.rate_limit || 60
            rate_key = "api_key:#{api_key.id}"

            case Hammer.check_rate(rate_key, 60_000, rate_limit) do
              {:allow, _count} ->
                conn
                |> PkiRaEngine.Api.IpWhitelistPlug.check(api_key)
                |> maybe_assign_api_key(api_key, tenant_id)

              {:deny, _limit} ->
                audit_rate_limited(api_key, tenant_id)

                conn
                |> put_resp_content_type("application/json")
                |> put_resp_header("retry-after", "60")
                |> send_resp(429, Jason.encode!(%{
                  error: "rate_limited",
                  retry_after: 60,
                  message: "Rate limit exceeded. Try again in 60 seconds."
                }))
                |> halt()

              {:error, reason} ->
                # Hammer error — fail closed (CA system must not bypass rate limiting)
                Logger.error("rate_limit_backend_error api_key=#{api_key.id} reason=#{inspect(reason)}")

                conn
                |> put_resp_content_type("application/json")
                |> send_resp(503, Jason.encode!(%{
                  error: "service_unavailable",
                  message: "Service temporarily unavailable. Please try again later."
                }))
                |> halt()
            end

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

  defp maybe_assign_api_key(%Plug.Conn{halted: true} = conn, _api_key, _tenant_id), do: conn
  defp maybe_assign_api_key(conn, api_key, tenant_id), do: assign_api_key(conn, api_key, tenant_id)

  defp assign_api_key(conn, api_key, tenant_id) do
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
  end

  defp audit_rate_limited(api_key, tenant_id) do
    PkiPlatformEngine.PlatformAudit.log("api_key_rate_limited", %{
      target_type: "api_key",
      target_id: api_key.id,
      tenant_id: tenant_id,
      portal: "ra",
      details: %{rate_limit: api_key.rate_limit, label: api_key.label}
    })
  rescue
    _ -> :ok
  end

  defp unauthorized(conn) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(401, Jason.encode!(%{error: "unauthorized"}))
    |> halt()
  end
end
