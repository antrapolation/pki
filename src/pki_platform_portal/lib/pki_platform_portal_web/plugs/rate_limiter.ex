defmodule PkiPlatformPortalWeb.Plugs.RateLimiter do
  @moduledoc """
  Rate limiting plug using Hammer.

  Limits requests by client IP. Configurable via plug options:
    - `:scale_ms` — time window in ms (default: 5 minutes)
    - `:limit` — max requests per window (default: 5)
    - `:key_prefix` — prefix for the rate limit bucket (default: "rate_limit")

  Returns 429 Too Many Requests when the limit is exceeded.

  X-Forwarded-For is only trusted when conn.remote_ip matches a configured
  trusted proxy. Configure via :pki_platform_portal, :trusted_proxies (list of IP strings).
  """

  import Plug.Conn
  require Logger

  def init(opts), do: opts

  def call(conn, opts) do
    if not rate_limit_enabled?() do
      conn
    else
      do_rate_limit(conn, opts)
    end
  end

  defp rate_limit_enabled? do
    Application.get_env(:pki_platform_portal, :rate_limit_enabled, true)
  end

  defp do_rate_limit(conn, opts) do
    prefix = Keyword.get(opts, :key_prefix, "rate_limit")
    scale_ms = Keyword.get(opts, :scale_ms, 5 * 60 * 1000)
    limit = Keyword.get(opts, :limit, 5)

    ip = client_ip(conn)
    key = "#{prefix}:#{ip}"

    case Hammer.check_rate(key, scale_ms, limit) do
      {:allow, _count} ->
        conn

      {:deny, _limit} ->
        Logger.warning("[rate_limit] #{prefix} limit exceeded for #{ip}")

        conn
        |> put_resp_header("retry-after", Integer.to_string(div(scale_ms, 1000)))
        |> put_status(429)
        |> Phoenix.Controller.put_view(PkiPlatformPortalWeb.SessionHTML)
        |> Phoenix.Controller.put_format(:html)
        |> Phoenix.Controller.render(:login,
          layout: false,
          error: "Too many attempts. Please wait a few minutes before trying again."
        )
        |> halt()

      {:error, reason} ->
        Logger.error("[rate_limit] Hammer error for #{key}: #{inspect(reason)}")

        conn
        |> put_status(503)
        |> Phoenix.Controller.put_view(PkiPlatformPortalWeb.SessionHTML)
        |> Phoenix.Controller.put_format(:html)
        |> Phoenix.Controller.render(:login,
          layout: false,
          error: "Service temporarily unavailable. Please try again."
        )
        |> halt()
    end
  end

  defp client_ip(conn) do
    remote = conn.remote_ip |> :inet.ntoa() |> to_string()
    trusted = Application.get_env(:pki_platform_portal, :trusted_proxies, [])

    if remote in trusted do
      case get_req_header(conn, "x-forwarded-for") do
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
