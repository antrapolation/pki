defmodule PkiTenantWeb.HostRouter do
  @moduledoc """
  Dispatches requests by hostname subdomain.
  <slug>.ca.<domain> -> CaRouter
  <slug>.ra.<domain> -> RaRouter
  """
  import Plug.Conn

  def init(opts), do: opts

  def call(conn, _opts) do
    case extract_service(conn.host) do
      :ca -> PkiTenantWeb.CaRouter.call(conn, PkiTenantWeb.CaRouter.init([]))
      :ra -> PkiTenantWeb.RaRouter.call(conn, PkiTenantWeb.RaRouter.init([]))
      _ -> conn |> send_resp(404, "Unknown service") |> halt()
    end
  end

  @doc false
  def extract_service(host) do
    case host |> String.split(".") do
      [_slug, "ca" | _] -> :ca
      [_slug, "ra" | _] -> :ra
      # For local dev: localhost defaults to CA
      ["localhost" | _] -> :ca
      _ -> :unknown
    end
  end
end
