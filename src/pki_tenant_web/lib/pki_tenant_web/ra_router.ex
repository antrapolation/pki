defmodule PkiTenantWeb.RaRouter do
  use Phoenix.Router
  import Phoenix.LiveView.Router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :protect_from_forgery
    plug :put_secure_browser_headers
  end

  scope "/", PkiTenantWeb.Ra do
    pipe_through :browser

    live "/", DashboardLive, :index
    live "/csrs", CsrsLive, :index
    live "/cert-profiles", CertProfilesLive, :index
    live "/api-keys", ApiKeysLive, :index
  end
end
