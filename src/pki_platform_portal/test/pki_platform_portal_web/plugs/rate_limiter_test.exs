defmodule PkiPlatformPortalWeb.Plugs.RateLimiterTest do
  use PkiPlatformPortalWeb.ConnCase

  alias PkiPlatformPortalWeb.Plugs.RateLimiter

  describe "allows requests under the limit" do
    test "first requests pass through", %{conn: conn} do
      prefix = "test_plat_#{System.unique_integer([:positive])}"
      opts = RateLimiter.init(key_prefix: prefix, limit: 3, scale_ms: 60_000)

      for _ <- 1..3 do
        result = RateLimiter.call(conn, opts)
        refute result.halted
      end
    end
  end

  describe "denies requests over the limit" do
    test "returns 429 when limit exceeded", %{conn: conn} do
      prefix = "test_plat_deny_#{System.unique_integer([:positive])}"
      opts = RateLimiter.init(key_prefix: prefix, limit: 2, scale_ms: 60_000)

      for _ <- 1..2, do: RateLimiter.call(conn, opts)

      result = RateLimiter.call(conn, opts)
      assert result.halted
      assert result.status == 429
    end

    test "429 response includes retry-after header", %{conn: conn} do
      prefix = "test_plat_retry_#{System.unique_integer([:positive])}"
      opts = RateLimiter.init(key_prefix: prefix, limit: 1, scale_ms: 300_000)

      RateLimiter.call(conn, opts)

      result = RateLimiter.call(conn, opts)
      assert result.halted

      retry_after = Plug.Conn.get_resp_header(result, "retry-after")
      assert retry_after == ["300"]
    end

    test "429 response renders login page with error message", %{conn: conn} do
      prefix = "test_plat_msg_#{System.unique_integer([:positive])}"
      opts = RateLimiter.init(key_prefix: prefix, limit: 1, scale_ms: 60_000)

      RateLimiter.call(conn, opts)

      result = RateLimiter.call(conn, opts)
      assert result.halted
      assert html_response(result, 429) =~ "Too many attempts"
    end
  end

  describe "client_ip proxy handling" do
    test "uses X-Forwarded-For when behind trusted proxy" do
      prev = Application.get_env(:pki_platform_portal, :trusted_proxies)
      Application.put_env(:pki_platform_portal, :trusted_proxies, ["127.0.0.1"])

      prefix = "test_plat_xff_#{System.unique_integer([:positive])}"
      opts = RateLimiter.init(key_prefix: prefix, limit: 1, scale_ms: 60_000)

      conn =
        Phoenix.ConnTest.build_conn()
        |> Plug.Conn.put_req_header("x-forwarded-for", "203.0.113.50")

      result = RateLimiter.call(conn, opts)
      refute result.halted

      result2 = RateLimiter.call(conn, opts)
      assert result2.halted

      # Different forwarded IP still allowed
      conn2 =
        Phoenix.ConnTest.build_conn()
        |> Plug.Conn.put_req_header("x-forwarded-for", "198.51.100.1")

      result3 = RateLimiter.call(conn2, opts)
      refute result3.halted

      if prev, do: Application.put_env(:pki_platform_portal, :trusted_proxies, prev),
        else: Application.delete_env(:pki_platform_portal, :trusted_proxies)
    end

    test "multi-proxy X-Forwarded-For skips trusted proxies right-to-left" do
      prev = Application.get_env(:pki_platform_portal, :trusted_proxies)
      Application.put_env(:pki_platform_portal, :trusted_proxies, ["127.0.0.1", "10.0.0.1"])

      prefix = "test_plat_multi_#{System.unique_integer([:positive])}"
      opts = RateLimiter.init(key_prefix: prefix, limit: 1, scale_ms: 60_000)

      conn =
        Phoenix.ConnTest.build_conn()
        |> Plug.Conn.put_req_header("x-forwarded-for", "203.0.113.1, 10.0.0.1")

      result = RateLimiter.call(conn, opts)
      refute result.halted

      result2 = RateLimiter.call(conn, opts)
      assert result2.halted

      if prev, do: Application.put_env(:pki_platform_portal, :trusted_proxies, prev),
        else: Application.delete_env(:pki_platform_portal, :trusted_proxies)
    end
  end

  describe "different IPs have independent limits" do
    test "separate IPs are tracked independently" do
      prefix = "test_plat_indep_#{System.unique_integer([:positive])}"
      opts = RateLimiter.init(key_prefix: prefix, limit: 1, scale_ms: 60_000)

      conn_a =
        Phoenix.ConnTest.build_conn()
        |> Map.put(:remote_ip, {10, 0, 0, 1})

      conn_b =
        Phoenix.ConnTest.build_conn()
        |> Map.put(:remote_ip, {10, 0, 0, 2})

      RateLimiter.call(conn_a, opts)
      result_a = RateLimiter.call(conn_a, opts)
      assert result_a.halted

      result_b = RateLimiter.call(conn_b, opts)
      refute result_b.halted
    end
  end

  describe "rate_limit_enabled flag" do
    test "bypasses rate limiting when disabled", %{conn: conn} do
      prev = Application.get_env(:pki_platform_portal, :rate_limit_enabled)
      Application.put_env(:pki_platform_portal, :rate_limit_enabled, false)

      prefix = "test_plat_disabled_#{System.unique_integer([:positive])}"
      opts = RateLimiter.init(key_prefix: prefix, limit: 1, scale_ms: 60_000)

      RateLimiter.call(conn, opts)
      RateLimiter.call(conn, opts)

      result = RateLimiter.call(conn, opts)
      refute result.halted

      if prev, do: Application.put_env(:pki_platform_portal, :rate_limit_enabled, prev),
        else: Application.delete_env(:pki_platform_portal, :rate_limit_enabled)
    end
  end
end
