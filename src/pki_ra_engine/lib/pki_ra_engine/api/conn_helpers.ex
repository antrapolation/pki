defmodule PkiRaEngine.Api.ConnHelpers do
  @moduledoc """
  Shared connection helpers for plug modules.
  Provides proxy-aware client IP resolution.
  """

  @doc """
  Returns the real client IP as a string, respecting X-Forwarded-For
  when the direct peer is a trusted proxy.
  """
  def client_ip(conn) do
    remote = conn.remote_ip |> :inet.ntoa() |> to_string()
    trusted = Application.get_env(:pki_ra_engine, :trusted_proxies, [])

    if remote in trusted do
      case Plug.Conn.get_req_header(conn, "x-forwarded-for") do
        [forwarded | _] ->
          forwarded
          |> String.split(",")
          |> Enum.map(&String.trim/1)
          |> Enum.reverse()
          |> Enum.drop_while(&(&1 in trusted))
          |> List.first(remote)

        [] ->
          remote
      end
    else
      remote
    end
  end
end
