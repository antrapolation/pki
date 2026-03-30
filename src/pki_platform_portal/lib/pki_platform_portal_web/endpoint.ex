defmodule PkiPlatformPortalWeb.Endpoint do
  use Phoenix.Endpoint, otp_app: :pki_platform_portal

  # signing_salt prevents cookie reuse across apps with the same secret_key_base.
  # Falls back to the compile-time default; set PLATFORM_SIGNING_SALT in .env for production.
  @signing_salt Application.compile_env(:pki_platform_portal, :signing_salt, "Pk7mQ3xN")

  @session_options [
    store: :cookie,
    key: "_pki_platform_portal_key",
    signing_salt: @signing_salt,
    encryption_salt: "pki_platform_enc",
    same_site: "Lax",
    secure: Application.compile_env(:pki_platform_portal, :cookie_secure, false),
    http_only: true
  ]

  socket "/live", Phoenix.LiveView.Socket,
    websocket: [connect_info: [session: @session_options]],
    longpoll: [connect_info: [session: @session_options]]

  plug Plug.Static,
    at: "/",
    from: :pki_platform_portal,
    gzip: not code_reloading?,
    only: PkiPlatformPortalWeb.static_paths(),
    raise_on_missing_only: code_reloading?

  if code_reloading? do
    socket "/phoenix/live_reload/socket", Phoenix.LiveReloader.Socket
    plug Phoenix.LiveReloader
    plug Phoenix.CodeReloader
  end

  plug Plug.RequestId
  plug Plug.Telemetry, event_prefix: [:phoenix, :endpoint]

  plug Plug.Parsers,
    parsers: [:urlencoded, :multipart, :json],
    pass: ["*/*"],
    json_decoder: Phoenix.json_library()

  plug Plug.MethodOverride
  plug Plug.Head
  plug Plug.Session, @session_options
  plug PkiPlatformPortalWeb.Router
end
