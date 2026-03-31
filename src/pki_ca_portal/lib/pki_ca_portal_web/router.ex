defmodule PkiCaPortalWeb.Router do
  use PkiCaPortalWeb, :router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {PkiCaPortalWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
  end

  pipeline :require_auth do
    plug PkiCaPortalWeb.Plugs.RequireAuth
  end

  pipeline :api do
    plug :accepts, ["json"]
  end

  # Public routes (no auth required)
  scope "/", PkiCaPortalWeb do
    pipe_through :browser

    get "/setup", SetupController, :new
    post "/setup", SetupController, :create
    get "/login", SessionController, :new
    post "/login", SessionController, :create
    delete "/logout", SessionController, :delete
    get "/change-password", PasswordController, :edit
    put "/change-password", PasswordController, :update
    get "/forgot-password", ForgotPasswordController, :new
    post "/forgot-password", ForgotPasswordController, :create
    put "/forgot-password", ForgotPasswordController, :update
  end

  # Protected routes (auth required)
  scope "/", PkiCaPortalWeb do
    pipe_through [:browser, :require_auth]

    live_session :authenticated, on_mount: PkiCaPortalWeb.Live.AuthHook do
      live "/", DashboardLive
      live "/users", UsersLive
      live "/keystores", KeystoresLive
      live "/ceremony", CeremonyLive
      live "/ca-instances", CaInstancesLive
      live "/audit-log", AuditLogLive
      live "/quick-setup", QuickSetupLive
      live "/profile", ProfileLive
    end
  end
end
