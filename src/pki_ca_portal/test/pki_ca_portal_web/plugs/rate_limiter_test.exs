defmodule PkiCaPortalWeb.Plugs.RateLimiterTest do
  use PkiCaPortalWeb.ConnCase

  alias PkiCaPortalWeb.Plugs.RateLimiter

  describe "allows requests under the limit" do
    test "first requests pass through", %{conn: conn} do
      prefix = "test_portal_#{System.unique_integer([:positive])}"
      opts = RateLimiter.init(key_prefix: prefix, limit: 3, scale_ms: 60_000)

      for _ <- 1..3 do
        result = RateLimiter.call(conn, opts)
        refute result.halted
      end
    end
  end

  describe "denies requests over the limit" do
    test "returns 429 when limit exceeded", %{conn: conn} do
      prefix = "test_portal_deny_#{System.unique_integer([:positive])}"
      opts = RateLimiter.init(key_prefix: prefix, limit: 2, scale_ms: 60_000)

      for _ <- 1..2, do: RateLimiter.call(conn, opts)

      result = RateLimiter.call(conn, opts)
      assert result.halted
      assert result.status == 429
    end

    test "429 response includes retry-after header", %{conn: conn} do
      prefix = "test_portal_retry_#{System.unique_integer([:positive])}"
      opts = RateLimiter.init(key_prefix: prefix, limit: 1, scale_ms: 300_000)

      RateLimiter.call(conn, opts)

      result = RateLimiter.call(conn, opts)
      assert result.halted

      retry_after = Plug.Conn.get_resp_header(result, "retry-after")
      assert retry_after == ["300"]
    end

    test "429 response renders login page with error message", %{conn: conn} do
      prefix = "test_portal_msg_#{System.unique_integer([:positive])}"
      opts = RateLimiter.init(key_prefix: prefix, limit: 1, scale_ms: 60_000)

      RateLimiter.call(conn, opts)

      result = RateLimiter.call(conn, opts)
      assert result.halted
      assert html_response(result, 429) =~ "Too many attempts"
    end
  end

  describe "client_ip proxy handling" do
    test "uses remote_ip by default", %{conn: conn} do
      prefix = "test_portal_ip_#{System.unique_integer([:positive])}"
      opts = RateLimiter.init(key_prefix: prefix, limit: 1, scale_ms: 60_000)

      result = RateLimiter.call(conn, opts)
      refute result.halted

      # Second call exhausts limit for 127.0.0.1
      result2 = RateLimiter.call(conn, opts)
      assert result2.halted
    end

    test "uses X-Forwarded-For when behind trusted proxy" do
      prev = Application.get_env(:pki_ca_portal, :trusted_proxies)
      Application.put_env(:pki_ca_portal, :trusted_proxies, ["127.0.0.1"])

      prefix = "test_portal_xff_#{System.unique_integer([:positive])}"
      opts = RateLimiter.init(key_prefix: prefix, limit: 1, scale_ms: 60_000)

      conn = Phoenix.ConnTest.build_conn()
      conn = Plug.Conn.put_req_header(conn, "x-forwarded-for", "203.0.113.50")

      result = RateLimiter.call(conn, opts)
      refute result.halted

      # Second request from same forwarded IP is blocked
      result2 = RateLimiter.call(conn, opts)
      assert result2.halted

      # Different forwarded IP is allowed
      conn2 =
        Phoenix.ConnTest.build_conn()
        |> Plug.Conn.put_req_header("x-forwarded-for", "198.51.100.1")

      result3 = RateLimiter.call(conn2, opts)
      refute result3.halted

      if prev, do: Application.put_env(:pki_ca_portal, :trusted_proxies, prev),
        else: Application.delete_env(:pki_ca_portal, :trusted_proxies)
    end

    test "multi-proxy X-Forwarded-For skips trusted proxies right-to-left" do
      prev = Application.get_env(:pki_ca_portal, :trusted_proxies)
      Application.put_env(:pki_ca_portal, :trusted_proxies, ["127.0.0.1", "10.0.0.1"])

      prefix = "test_portal_multi_#{System.unique_integer([:positive])}"
      opts = RateLimiter.init(key_prefix: prefix, limit: 1, scale_ms: 60_000)

      # Client -> trusted 10.0.0.1 -> trusted 127.0.0.1
      conn =
        Phoenix.ConnTest.build_conn()
        |> Plug.Conn.put_req_header("x-forwarded-for", "203.0.113.1, 10.0.0.1")

      result = RateLimiter.call(conn, opts)
      refute result.halted

      # Second request keyed on 203.0.113.1
      result2 = RateLimiter.call(conn, opts)
      assert result2.halted

      if prev, do: Application.put_env(:pki_ca_portal, :trusted_proxies, prev),
        else: Application.delete_env(:pki_ca_portal, :trusted_proxies)
    end
  end

  describe "different IPs have independent limits" do
    test "separate IPs are tracked independently" do
      prefix = "test_portal_indep_#{System.unique_integer([:positive])}"
      opts = RateLimiter.init(key_prefix: prefix, limit: 1, scale_ms: 60_000)

      conn_a =
        Phoenix.ConnTest.build_conn()
        |> Map.put(:remote_ip, {10, 0, 0, 1})

      conn_b =
        Phoenix.ConnTest.build_conn()
        |> Map.put(:remote_ip, {10, 0, 0, 2})

      # Exhaust limit for IP A
      RateLimiter.call(conn_a, opts)
      result_a = RateLimiter.call(conn_a, opts)
      assert result_a.halted

      # IP B still allowed
      result_b = RateLimiter.call(conn_b, opts)
      refute result_b.halted
    end
  end

  describe "rate_limit_enabled flag" do
    test "bypasses rate limiting when disabled", %{conn: conn} do
      prev = Application.get_env(:pki_ca_portal, :rate_limit_enabled)
      Application.put_env(:pki_ca_portal, :rate_limit_enabled, false)

      prefix = "test_portal_disabled_#{System.unique_integer([:positive])}"
      opts = RateLimiter.init(key_prefix: prefix, limit: 1, scale_ms: 60_000)

      # Exhaust what would be the limit
      RateLimiter.call(conn, opts)
      RateLimiter.call(conn, opts)

      # Should still pass — rate limiting is off
      result = RateLimiter.call(conn, opts)
      refute result.halted

      if prev, do: Application.put_env(:pki_ca_portal, :rate_limit_enabled, prev),
        else: Application.delete_env(:pki_ca_portal, :rate_limit_enabled)
    end
  end
end
