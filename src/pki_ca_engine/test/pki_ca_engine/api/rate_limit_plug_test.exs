defmodule PkiCaEngine.Api.RateLimitPlugTest do
  # async: false because proxy tests mutate global Application env (:trusted_proxies)
  use ExUnit.Case, async: false

  alias PkiCaEngine.Api.RateLimitPlug

  setup do
    prefix = "test_ca_#{System.unique_integer([:positive])}"
    opts = RateLimitPlug.init(key_prefix: prefix, limit: 3, scale_ms: 60_000)
    {:ok, opts: opts, prefix: prefix}
  end

  defp build_conn(remote_ip \\ {127, 0, 0, 1}) do
    Plug.Test.conn(:post, "/login")
    |> Map.put(:remote_ip, remote_ip)
  end

  describe "init/1" do
    test "sets defaults" do
      opts = RateLimitPlug.init([])
      assert opts.key_prefix == "ca_auth"
      assert opts.limit == 10
      assert opts.scale_ms == 60_000
    end

    test "accepts custom options" do
      opts = RateLimitPlug.init(key_prefix: "custom", limit: 5, scale_ms: 120_000)
      assert opts.key_prefix == "custom"
      assert opts.limit == 5
      assert opts.scale_ms == 120_000
    end
  end

  describe "call/2 — allow and deny" do
    test "allows requests under the limit", %{opts: opts} do
      for _ <- 1..3 do
        conn = build_conn()
        result = RateLimitPlug.call(conn, opts)
        refute result.halted
      end
    end

    test "denies request exceeding the limit with 429", %{opts: opts} do
      for _ <- 1..3, do: RateLimitPlug.call(build_conn(), opts)

      result = RateLimitPlug.call(build_conn(), opts)
      assert result.halted
      assert result.status == 429
    end

    test "429 response includes retry-after header", %{opts: opts} do
      for _ <- 1..3, do: RateLimitPlug.call(build_conn(), opts)

      result = RateLimitPlug.call(build_conn(), opts)
      assert result.halted

      {_, retry_after} =
        Enum.find(result.resp_headers, fn {k, _} -> k == "retry-after" end)

      assert retry_after == "60"
    end

    test "429 response body is JSON with error key", %{opts: opts} do
      for _ <- 1..3, do: RateLimitPlug.call(build_conn(), opts)

      result = RateLimitPlug.call(build_conn(), opts)
      body = Jason.decode!(result.resp_body)
      assert body["error"] == "rate_limited"
    end

    test "different IPs have independent limits", %{opts: opts} do
      # Exhaust limit for IP A
      for _ <- 1..3, do: RateLimitPlug.call(build_conn({10, 0, 0, 1}), opts)

      # IP A is now blocked
      result_a = RateLimitPlug.call(build_conn({10, 0, 0, 1}), opts)
      assert result_a.halted

      # IP B should still be allowed
      result_b = RateLimitPlug.call(build_conn({10, 0, 0, 2}), opts)
      refute result_b.halted
    end
  end

  describe "client_ip/1 — proxy handling" do
    test "uses remote_ip when not behind trusted proxy", %{opts: opts} do
      conn = build_conn({10, 0, 0, 99})
      result = RateLimitPlug.call(conn, opts)
      refute result.halted
    end

    test "uses X-Forwarded-For when behind trusted proxy" do
      prev = Application.get_env(:pki_ca_engine, :trusted_proxies)
      Application.put_env(:pki_ca_engine, :trusted_proxies, ["127.0.0.1"])

      prefix = "test_proxy_#{System.unique_integer([:positive])}"
      opts = RateLimitPlug.init(key_prefix: prefix, limit: 2, scale_ms: 60_000)

      make_conn = fn ->
        Plug.Test.conn(:post, "/login")
        |> Map.put(:remote_ip, {127, 0, 0, 1})
        |> Plug.Conn.put_req_header("x-forwarded-for", "203.0.113.50, 127.0.0.1")
      end

      # First two requests should be allowed
      for _ <- 1..2, do: RateLimitPlug.call(make_conn.(), opts)

      # Third request should be denied (keyed on 203.0.113.50)
      result = RateLimitPlug.call(make_conn.(), opts)
      assert result.halted

      # Different forwarded IP should still be allowed
      conn2 =
        Plug.Test.conn(:post, "/login")
        |> Map.put(:remote_ip, {127, 0, 0, 1})
        |> Plug.Conn.put_req_header("x-forwarded-for", "198.51.100.10")

      result2 = RateLimitPlug.call(conn2, opts)
      refute result2.halted

      if prev, do: Application.put_env(:pki_ca_engine, :trusted_proxies, prev),
        else: Application.delete_env(:pki_ca_engine, :trusted_proxies)
    end

    test "multi-proxy X-Forwarded-For skips trusted proxies right-to-left" do
      prev = Application.get_env(:pki_ca_engine, :trusted_proxies)
      Application.put_env(:pki_ca_engine, :trusted_proxies, ["127.0.0.1", "10.0.0.1"])

      prefix = "test_multiproxy_#{System.unique_integer([:positive])}"
      opts = RateLimitPlug.init(key_prefix: prefix, limit: 1, scale_ms: 60_000)

      make_conn = fn ->
        Plug.Test.conn(:post, "/login")
        |> Map.put(:remote_ip, {127, 0, 0, 1})
        |> Plug.Conn.put_req_header("x-forwarded-for", "203.0.113.1, 10.0.0.1, 127.0.0.1")
      end

      # First request uses 203.0.113.1 as the key
      result = RateLimitPlug.call(make_conn.(), opts)
      refute result.halted

      # Second request should be denied (limit=1)
      result2 = RateLimitPlug.call(make_conn.(), opts)
      assert result2.halted

      if prev, do: Application.put_env(:pki_ca_engine, :trusted_proxies, prev),
        else: Application.delete_env(:pki_ca_engine, :trusted_proxies)
    end
  end

  describe "rate_limit_enabled flag" do
    test "bypasses rate limiting when disabled", %{opts: opts} do
      Application.put_env(:pki_ca_engine, :rate_limit_enabled, false)

      for _ <- 1..5, do: RateLimitPlug.call(build_conn(), opts)

      result = RateLimitPlug.call(build_conn(), opts)
      refute result.halted

      Application.put_env(:pki_ca_engine, :rate_limit_enabled, true)
    end

    test "enforces rate limiting when enabled (default)", %{opts: opts} do
      for _ <- 1..3, do: RateLimitPlug.call(build_conn(), opts)

      result = RateLimitPlug.call(build_conn(), opts)
      assert result.halted
      assert result.status == 429
    end
  end
end
