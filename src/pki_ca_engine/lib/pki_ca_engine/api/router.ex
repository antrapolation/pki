defmodule PkiCaEngine.Api.Router do
  @moduledoc """
  Main Plug.Router -- public routes and forwards to authenticated router.
  """

  use Plug.Router

  plug PkiPlatformEngine.Plugs.ClearTenantPrefix
  plug :match
  plug Plug.Parsers, parsers: [:json], json_decoder: Jason
  plug :dispatch

  # Public health check
  get "/health" do
    send_resp(conn, 200, Jason.encode!(%{status: "ok"}))
  end

  # Auth endpoints (rate-limited, no token required)
  forward "/api/v1/auth", to: PkiCaEngine.Api.AuthRouter

  # Everything else under /api/v1 requires authentication
  forward "/api/v1", to: PkiCaEngine.Api.AuthenticatedRouter

  match _ do
    send_resp(conn, 404, Jason.encode!(%{error: "not_found"}))
  end
end
