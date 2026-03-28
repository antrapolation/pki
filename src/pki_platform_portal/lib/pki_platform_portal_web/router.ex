defmodule PkiPlatformPortalWeb.Router do
  use PkiPlatformPortalWeb, :router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {PkiPlatformPortalWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
  end

  pipeline :require_auth do
    plug PkiPlatformPortalWeb.Plugs.RequireAuth
  end

  pipeline :api do
    plug :accepts, ["json"]
  end

  # Public routes (no auth required)
  scope "/", PkiPlatformPortalWeb do
    pipe_through :browser

    get "/login", SessionController, :new
    post "/login", SessionController, :create
    delete "/logout", SessionController, :delete
  end

  # Protected routes (auth required)
  scope "/", PkiPlatformPortalWeb do
    pipe_through [:browser, :require_auth]

    live_session :authenticated, on_mount: PkiPlatformPortalWeb.Live.AuthHook do
      live "/", DashboardLive
      live "/tenants", TenantsLive
    end
  end
end
