defmodule PkiRaEngine.Api.RateLimitPlug do
  @moduledoc """
  Rate-limits authentication endpoints per client IP.

  Returns 429 Too Many Requests when the limit is exceeded.

  ## Options

    * `:key_prefix` — bucket prefix (default: `"ra_auth"`)
    * `:limit` — max requests per window (default: 10)
    * `:scale_ms` — time window in ms (default: 60_000)
    * `:trusted_proxies` — list of trusted proxy IPs for X-Forwarded-For (default: from app config)

  """

  import Plug.Conn
  require Logger

  @default_limit 10
  @default_scale_ms 60_000

  def init(opts) do
    %{
      key_prefix: Keyword.get(opts, :key_prefix, "ra_auth"),
      limit: Keyword.get(opts, :limit, @default_limit),
      scale_ms: Keyword.get(opts, :scale_ms, @default_scale_ms)
    }
  end

  def call(conn, opts) do
    if not rate_limit_enabled?() do
      conn
    else
      ip = client_ip(conn)
      key = "#{opts.key_prefix}:#{ip}"

      case Hammer.check_rate(key, opts.scale_ms, opts.limit) do
        {:allow, _count} ->
          conn

        {:deny, _limit} ->
          retry_after = div(opts.scale_ms, 1000)

          conn
          |> put_resp_content_type("application/json")
          |> put_resp_header("retry-after", Integer.to_string(retry_after))
          |> send_resp(429, Jason.encode!(%{error: "rate_limited", message: "Too many attempts. Try again later."}))
          |> halt()

        {:error, reason} ->
          Logger.error("[rate_limit] Hammer error for #{key}: #{inspect(reason)}")

          conn
          |> put_resp_content_type("application/json")
          |> send_resp(503, Jason.encode!(%{error: "service_unavailable", message: "Service temporarily unavailable."}))
          |> halt()
      end
    end
  end

  defp rate_limit_enabled? do
    Application.get_env(:pki_ra_engine, :rate_limit_enabled, true)
  end

  defp client_ip(conn) do
    remote = conn.remote_ip |> :inet.ntoa() |> to_string()
    trusted = Application.get_env(:pki_ra_engine, :trusted_proxies, [])

    if remote in trusted do
      case Plug.Conn.get_req_header(conn, "x-forwarded-for") do
        [forwarded | _] ->
          forwarded
          |> String.split(",")
          |> Enum.map(&String.trim/1)
          |> Enum.reverse()
          |> Enum.drop_while(&(&1 in trusted))
          |> List.first(remote)

        [] ->
          remote
      end
    else
      remote
    end
  end
end
