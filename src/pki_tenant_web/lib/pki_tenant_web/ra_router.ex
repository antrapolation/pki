defmodule PkiTenantWeb.RaRouter do
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

  # Authenticated RA routes
  scope "/", PkiTenantWeb.Ra do
    pipe_through :browser

    live_session :ra_authenticated,
      on_mount: [{PkiTenantWeb.Live.AuthHook, :ra}],
      layout: {PkiTenantWeb.Layouts, :ra_app} do
      live "/", DashboardLive, :index
      live "/ra-instances", RaInstancesLive, :index
      live "/ca-connection", CaConnectionLive, :index
      live "/csrs", CsrsLive, :index
      live "/cert-profiles", CertProfilesLive, :index
      live "/certificates", CertificatesLive, :index
      live "/api-keys", ApiKeysLive, :index
      live "/service-configs", ServiceConfigsLive, :index
      live "/setup-wizard", SetupWizardLive, :index
    end
  end

  # Shared live views (not under a portal-specific alias).
  scope "/", PkiTenantWeb do
    pipe_through :browser

    live_session :ra_shared,
      on_mount: [{PkiTenantWeb.Live.AuthHook, :ra}],
      layout: {PkiTenantWeb.Layouts, :ra_app} do
      live "/profile", ProfileLive, :index
    end
  end
end
