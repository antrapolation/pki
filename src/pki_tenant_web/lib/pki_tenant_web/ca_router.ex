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
      live "/issuer-keys", IssuerKeysLive, :index
      live "/ceremonies", CeremonyLive, :index
      live "/certificates", CertificatesLive, :index
    end
  end
end
