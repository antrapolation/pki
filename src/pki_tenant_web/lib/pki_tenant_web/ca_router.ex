defmodule PkiTenantWeb.CaRouter do
  use PkiTenantWeb, :router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {PkiTenantWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
  end

  pipeline :api do
    plug :accepts, ["json"]
  end

  # Health check (unauthenticated JSON endpoint)
  scope "/", PkiTenantWeb do
    pipe_through :api

    get "/health", HealthController, :show
  end

  # Public routes (no auth required)
  scope "/", PkiTenantWeb do
    pipe_through :browser

    get "/login", SessionController, :new
    post "/login", SessionController, :create
    delete "/logout", SessionController, :delete
  end

  # Authenticated CA routes
  scope "/", PkiTenantWeb.Ca do
    pipe_through :browser

    live_session :ca_authenticated,
      on_mount: [{PkiTenantWeb.Live.AuthHook, :ca}],
      layout: {PkiTenantWeb.Layouts, :ca_app} do
      live "/", DashboardLive, :index
      live "/ceremonies", CeremonyLive, :index
      live "/ceremonies/custodian", CeremonyCustodianLive, :index
      live "/issuer-keys", IssuerKeysLive, :index
      live "/certificates", CertificatesLive, :index
      live "/hsm-devices", HsmDevicesLive, :index
      live "/keystores", KeystoresLive, :index
    end

    # Printable ceremony transcript — plain controller, bypasses the
    # ca_app layout so the page renders cleanly for print.
    get "/ceremonies/:id/transcript", CeremonyTranscriptController, :show
  end

  # Shared live views (not under a portal-specific alias). Same live_session
  # so the ca_app layout applies.
  scope "/", PkiTenantWeb do
    pipe_through :browser

    live_session :ca_shared,
      on_mount: [{PkiTenantWeb.Live.AuthHook, :ca}],
      layout: {PkiTenantWeb.Layouts, :ca_app} do
      live "/profile", ProfileLive, :index
    end
  end
end
