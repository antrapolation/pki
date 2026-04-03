defmodule PkiCaEngine.Api.AuthRouter do
  @moduledoc """
  Router for public authentication endpoints.
  Applies per-IP rate limiting to mutation endpoints (login, register).
  Read-only endpoints (needs-setup) are not rate-limited.
  """

  use Plug.Router

  @rate_limit_opts PkiCaEngine.Api.RateLimitPlug.init([])

  plug :match
  plug :dispatch

  post "/login" do
    conn
    |> PkiCaEngine.Api.RateLimitPlug.call(@rate_limit_opts)
    |> case do
      %{halted: true} = halted -> halted
      conn -> PkiCaEngine.Api.AuthController.login(conn)
    end
  end

  post "/register" do
    conn
    |> PkiCaEngine.Api.RateLimitPlug.call(@rate_limit_opts)
    |> case do
      %{halted: true} = halted -> halted
      conn -> PkiCaEngine.Api.AuthController.register(conn)
    end
  end

  get "/needs-setup" do
    PkiCaEngine.Api.AuthController.needs_setup(conn)
  end
end
