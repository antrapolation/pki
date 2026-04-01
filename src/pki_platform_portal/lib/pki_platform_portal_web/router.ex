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
    plug PkiPlatformPortalWeb.Plugs.RequireSetup
    plug PkiPlatformPortalWeb.Plugs.RequireAuth
  end

  pipeline :redirect_to_setup do
    plug PkiPlatformPortalWeb.Plugs.RequireSetup
  end

  pipeline :api do
    plug :accepts, ["json"]
  end

  # Setup route (no auth, no setup check)
  scope "/", PkiPlatformPortalWeb do
    pipe_through :browser

    live_session :setup do
      live "/setup", SetupLive
    end
  end

  # Public routes (redirect to setup if no superadmin exists)
  scope "/", PkiPlatformPortalWeb do
    pipe_through [:browser, :redirect_to_setup]

    get "/login", SessionController, :new
    post "/login", SessionController, :create
    delete "/logout", SessionController, :delete

    get "/forgot-password", ForgotPasswordController, :new
    post "/forgot-password", ForgotPasswordController, :create
    put "/forgot-password", ForgotPasswordController, :update
  end

  # Protected routes
  scope "/", PkiPlatformPortalWeb do
    pipe_through [:browser, :require_auth]

    live_session :authenticated, on_mount: PkiPlatformPortalWeb.Live.AuthHook do
      live "/", DashboardLive
      live "/tenants", TenantsLive
      live "/tenants/new", TenantNewLive
      live "/tenants/:id", TenantDetailLive
      live "/hsm-devices", HsmDevicesLive
      live "/system", SystemLive
      live "/admins", AdminsLive
      live "/profile", ProfileLive
    end
  end
end
