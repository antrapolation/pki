defmodule PkiRaEngine.Api.AuthRouter do
  @moduledoc """
  Router for public authentication endpoints.
  Applies per-IP rate limiting before dispatching to the auth controller.
  """

  use Plug.Router

  plug PkiRaEngine.Api.RateLimitPlug
  plug :match
  plug :dispatch

  post "/login" do
    PkiRaEngine.Api.AuthController.login(conn)
  end

  post "/register" do
    PkiRaEngine.Api.AuthController.register(conn)
  end

  get "/needs-setup" do
    PkiRaEngine.Api.AuthController.needs_setup(conn)
  end

end
