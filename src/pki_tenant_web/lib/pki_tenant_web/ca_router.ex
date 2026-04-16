defmodule PkiTenantWeb.CaRouter do
  use Phoenix.Router
  import Phoenix.LiveView.Router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :protect_from_forgery
    plug :put_secure_browser_headers
  end

  scope "/", PkiTenantWeb.Ca do
    pipe_through :browser

    live "/", DashboardLive, :index
    live "/issuer-keys", IssuerKeysLive, :index
    live "/ceremonies", CeremonyLive, :index
    live "/certificates", CertificatesLive, :index
  end
end
