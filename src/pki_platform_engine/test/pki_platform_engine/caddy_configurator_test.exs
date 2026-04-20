defmodule PkiPlatformEngine.CaddyConfiguratorTest do
  @moduledoc """
  Unit coverage for the Caddy admin-API wrapper.

  The HTTP call itself isn't exercised — when Caddy isn't running
  (the default in CI and dev-without-proxy) the wrapper rescues to
  `{:error, :caddy_unavailable}`. We verify:

    * `build_route/2` produces the exact JSON shape Caddy's
      `/config/apps/http/servers/srv0/routes` endpoint expects, and
    * `add_route/2` / `remove_route/1` both fail closed — they never
      crash the caller when Caddy is unreachable.
  """
  use ExUnit.Case, async: false

  alias PkiPlatformEngine.CaddyConfigurator

  setup do
    prev = Application.get_env(:pki_platform_engine, :base_domain)
    Application.put_env(:pki_platform_engine, :base_domain, "example.test")

    on_exit(fn ->
      if prev,
        do: Application.put_env(:pki_platform_engine, :base_domain, prev),
        else: Application.delete_env(:pki_platform_engine, :base_domain)
    end)

    :ok
  end

  describe "build_route/2" do
    test "includes the three subdomains (ca/ra/ocsp) and the upstream port" do
      route = CaddyConfigurator.build_route("acme", 5001)

      assert route["@id"] == "route-acme"

      [match] = route["match"]
      assert "acme.ca.example.test" in match["host"]
      assert "acme.ra.example.test" in match["host"]
      assert "acme.ocsp.example.test" in match["host"]

      [handle] = route["handle"]
      assert handle["handler"] == "reverse_proxy"
      assert [%{"dial" => "localhost:5001"}] = handle["upstreams"]
    end

    test "uses the configured base_domain" do
      Application.put_env(:pki_platform_engine, :base_domain, "other.test")
      route = CaddyConfigurator.build_route("foo", 5010)
      [match] = route["match"]
      assert Enum.all?(match["host"], &String.ends_with?(&1, ".other.test"))
    end
  end

  describe "add_route/2 and remove_route/1 (caddy unavailable)" do
    test "add_route returns {:error, _} without raising when no Caddy is listening" do
      assert match?({:error, _}, CaddyConfigurator.add_route("caddy-unavailable-test", 5099))
    end

    test "remove_route returns {:error, _} without raising when no Caddy is listening" do
      assert match?({:error, _}, CaddyConfigurator.remove_route("caddy-unavailable-test"))
    end
  end
end
