defmodule PkiCaEngine.Api.RateLimitPlug do
  @moduledoc """
  Rate-limits authentication endpoints to 10 attempts per minute per IP.

  Returns 429 Too Many Requests when the limit is exceeded.
  The limit is intentionally conservative to slow brute-force attacks on
  the CA engine's credential store.
  """

  import Plug.Conn

  @limit 10
  @scale_ms 60_000

  def init(opts), do: opts

  def call(conn, _opts) do
    ip = conn.remote_ip |> :inet.ntoa() |> to_string()

    case Hammer.check_rate("ca_auth:#{ip}", @scale_ms, @limit) do
      {:allow, _count} ->
        conn

      {:deny, _limit} ->
        conn
        |> put_resp_content_type("application/json")
        |> send_resp(429, Jason.encode!(%{error: "rate_limited", message: "Too many attempts. Try again later."}))
        |> halt()
    end
  end
end
