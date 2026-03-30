defmodule PkiCaEngine.Api.AuthRouter do
  @moduledoc """
  Router for public authentication endpoints.
  Applies per-IP rate limiting before dispatching to the auth controller.
  """

  use Plug.Router

  plug PkiCaEngine.Api.RateLimitPlug
  plug :match
  plug :dispatch

  post "/login" do
    PkiCaEngine.Api.AuthController.login(conn)
  end

  post "/register" do
    PkiCaEngine.Api.AuthController.register(conn)
  end

  get "/needs-setup" do
    PkiCaEngine.Api.AuthController.needs_setup(conn)
  end

end
