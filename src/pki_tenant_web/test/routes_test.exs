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

    test "has /ca-instances route backed by Ca.CaInstancesLive" do
      assert "/ca-instances" in live_paths(@ca_routes)

      route = Enum.find(@ca_routes, fn r -> r.path == "/ca-instances" end)
      assert route.metadata.phoenix_live_view |> elem(0) == PkiTenantWeb.Ca.CaInstancesLive
    end

    test "has /users route backed by Ca.UsersLive" do
      assert "/users" in live_paths(@ca_routes)

      route = Enum.find(@ca_routes, fn r -> r.path == "/users" end)
      assert route.metadata.phoenix_live_view |> elem(0) == PkiTenantWeb.Ca.UsersLive
    end

    test "has /audit-log route backed by Ca.AuditLogLive" do
      assert "/audit-log" in live_paths(@ca_routes)

      route = Enum.find(@ca_routes, fn r -> r.path == "/audit-log" end)
      assert route.metadata.phoenix_live_view |> elem(0) == PkiTenantWeb.Ca.AuditLogLive
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

    test "has /service-configs route backed by Ra.ServiceConfigsLive" do
      assert "/service-configs" in live_paths(@ra_routes)

      route = Enum.find(@ra_routes, fn r -> r.path == "/service-configs" end)
      assert route.metadata.phoenix_live_view |> elem(0) == PkiTenantWeb.Ra.ServiceConfigsLive
    end

    test "has /ra-instances route backed by Ra.RaInstancesLive" do
      assert "/ra-instances" in live_paths(@ra_routes)

      route = Enum.find(@ra_routes, fn r -> r.path == "/ra-instances" end)
      assert route.metadata.phoenix_live_view |> elem(0) == PkiTenantWeb.Ra.RaInstancesLive
    end

    test "has /ca-connection route backed by Ra.CaConnectionLive" do
      assert "/ca-connection" in live_paths(@ra_routes)

      route = Enum.find(@ra_routes, fn r -> r.path == "/ca-connection" end)
      assert route.metadata.phoenix_live_view |> elem(0) == PkiTenantWeb.Ra.CaConnectionLive
    end

    test "has /users route backed by Ra.UsersLive" do
      assert "/users" in live_paths(@ra_routes)

      route = Enum.find(@ra_routes, fn r -> r.path == "/users" end)
      assert route.metadata.phoenix_live_view |> elem(0) == PkiTenantWeb.Ra.UsersLive
    end

    test "has /audit-log route backed by Ra.AuditLogLive" do
      assert "/audit-log" in live_paths(@ra_routes)

      route = Enum.find(@ra_routes, fn r -> r.path == "/audit-log" end)
      assert route.metadata.phoenix_live_view |> elem(0) == PkiTenantWeb.Ra.AuditLogLive
    end

    test "has /welcome route backed by Ra.WelcomeLive" do
      assert "/welcome" in live_paths(@ra_routes)

      route = Enum.find(@ra_routes, fn r -> r.path == "/welcome" end)
      assert route.metadata.phoenix_live_view |> elem(0) == PkiTenantWeb.Ra.WelcomeLive
    end

    test "has /validation route backed by Ra.ValidationStatusLive" do
      assert "/validation" in live_paths(@ra_routes)

      route = Enum.find(@ra_routes, fn r -> r.path == "/validation" end)
      assert route.metadata.phoenix_live_view |> elem(0) == PkiTenantWeb.Ra.ValidationStatusLive
    end

    test "has /profile route backed by the shared ProfileLive" do
      assert "/profile" in live_paths(@ra_routes)

      route = Enum.find(@ra_routes, fn r -> r.path == "/profile" end)
      assert route.metadata.phoenix_live_view |> elem(0) == PkiTenantWeb.ProfileLive
    end
  end
end
