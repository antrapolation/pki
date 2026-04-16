defmodule PkiTenantWeb.Endpoint do
  use Phoenix.Endpoint, otp_app: :pki_tenant_web

  @session_options [
    store: :cookie,
    key: "_pki_tenant_key",
    signing_salt: "tenant_salt"
  ]

  socket "/live", Phoenix.LiveView.Socket,
    websocket: [connect_info: [session: @session_options]]

  plug Plug.Static,
    at: "/",
    from: :pki_tenant_web,
    gzip: false,
    only: PkiTenantWeb.static_paths()

  plug Plug.RequestId
  plug Plug.Telemetry, event_prefix: [:phoenix, :endpoint]

  plug Plug.Parsers,
    parsers: [:urlencoded, :multipart, :json],
    pass: ["*/*"],
    json_decoder: Phoenix.json_library()

  plug Plug.MethodOverride
  plug Plug.Head
  plug Plug.Session, @session_options
  plug PkiTenantWeb.HostRouter
end
