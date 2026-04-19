defmodule PkiTenantWeb.RoutesTest do
  use ExUnit.Case, async: true

  @ca_routes Phoenix.Router.routes(PkiTenantWeb.CaRouter)
  @ra_routes Phoenix.Router.routes(PkiTenantWeb.RaRouter)

  defp live_paths(routes) do
    routes
    |> Enum.filter(fn r -> r.plug == Phoenix.LiveView.Plug end)
    |> Enum.map(fn r -> r.path end)
  end

  describe "CaRouter" do
    test "has dashboard route /" do
      assert "/" in live_paths(@ca_routes)
    end

    test "has /ceremonies route" do
      assert "/ceremonies" in live_paths(@ca_routes)
    end

    test "has /ceremonies/custodian route" do
      assert "/ceremonies/custodian" in live_paths(@ca_routes)
    end

    test "has /issuer-keys route" do
      assert "/issuer-keys" in live_paths(@ca_routes)
    end

    test "has /certificates route" do
      assert "/certificates" in live_paths(@ca_routes)
    end

    test "has /ceremonies/:id/transcript printable route" do
      # Non-LiveView controller route.
      paths = @ca_routes |> Enum.map(& &1.path)
      assert "/ceremonies/:id/transcript" in paths

      route =
        Enum.find(@ca_routes, fn r -> r.path == "/ceremonies/:id/transcript" end)

      assert route.verb == :get
      assert route.plug == PkiTenantWeb.Ca.CeremonyTranscriptController
    end

    test "has /profile route backed by the shared ProfileLive" do
      assert "/profile" in live_paths(@ca_routes)

      route = Enum.find(@ca_routes, fn r -> r.path == "/profile" end)
      assert route.metadata.phoenix_live_view |> elem(0) == PkiTenantWeb.ProfileLive
    end

    test "has /hsm-devices route backed by Ca.HsmDevicesLive" do
      assert "/hsm-devices" in live_paths(@ca_routes)

      route = Enum.find(@ca_routes, fn r -> r.path == "/hsm-devices" end)
      assert route.metadata.phoenix_live_view |> elem(0) == PkiTenantWeb.Ca.HsmDevicesLive
    end

    test "has /keystores route backed by Ca.KeystoresLive" do
      assert "/keystores" in live_paths(@ca_routes)

      route = Enum.find(@ca_routes, fn r -> r.path == "/keystores" end)
      assert route.metadata.phoenix_live_view |> elem(0) == PkiTenantWeb.Ca.KeystoresLive
    end
  end

  describe "RaRouter" do
    test "has dashboard route /" do
      assert "/" in live_paths(@ra_routes)
    end

    test "has /csrs route" do
      assert "/csrs" in live_paths(@ra_routes)
    end

    test "has /cert-profiles route" do
      assert "/cert-profiles" in live_paths(@ra_routes)
    end

    test "has /certificates route" do
      assert "/certificates" in live_paths(@ra_routes)
    end

    test "has /api-keys route" do
      assert "/api-keys" in live_paths(@ra_routes)
    end

    test "has /setup-wizard route" do
      assert "/setup-wizard" in live_paths(@ra_routes)
    end

    test "has /profile route backed by the shared ProfileLive" do
      assert "/profile" in live_paths(@ra_routes)

      route = Enum.find(@ra_routes, fn r -> r.path == "/profile" end)
      assert route.metadata.phoenix_live_view |> elem(0) == PkiTenantWeb.ProfileLive
    end
  end
end
