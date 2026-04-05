defmodule PkiRaEngine.Api.ConnHelpers do
  @moduledoc """
  Shared helpers for plug modules and API serialization.
  """

  @doc "Format datetime as `YYYY-MM-DD HH:MM:SS` (no T, no Z)."
  def format_datetime(nil), do: nil
  def format_datetime(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S")
  def format_datetime(%NaiveDateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S")
  def format_datetime(other), do: to_string(other)

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
