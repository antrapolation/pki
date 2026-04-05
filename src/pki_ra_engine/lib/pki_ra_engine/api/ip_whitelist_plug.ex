defmodule PkiRaEngine.Api.IpWhitelistPlug do
  @moduledoc """
  Checks client IP against an API key's ip_whitelist.
  Empty whitelist = allow all. Supports IPv4 and IPv6 CIDR notation.
  """

  import Plug.Conn
  require Logger

  def check(conn, %{ip_whitelist: []} = _api_key), do: conn
  def check(conn, %{ip_whitelist: nil} = _api_key), do: conn

  def check(conn, api_key) do
    client_ip = client_ip_string(conn)

    if ip_in_whitelist?(client_ip, api_key.ip_whitelist) do
      conn
    else
      audit_ip_rejected(api_key, client_ip, conn.assigns[:tenant_id])

      conn
      |> put_resp_content_type("application/json")
      |> send_resp(403, Jason.encode!(%{
        error: "ip_not_allowed",
        message: "Request from this IP address is not permitted."
      }))
      |> halt()
    end
  end

  defp client_ip_string(conn) do
    PkiRaEngine.Api.ConnHelpers.client_ip(conn)
  end

  defp ip_in_whitelist?(ip, whitelist) do
    Enum.any?(whitelist, fn cidr ->
      case parse_cidr(cidr) do
        {:ok, network, mask} ->
          ip_in_network?(ip, network, mask)

        :error ->
          Logger.warning("ip_whitelist: invalid CIDR entry ignored: #{inspect(cidr)}")
          false
      end
    end)
  end

  defp parse_cidr(cidr) do
    case String.split(cidr, "/") do
      [ip_str, mask_str] ->
        with {:ok, ip} <- :inet.parse_address(String.to_charlist(ip_str)),
             {mask, ""} <- Integer.parse(mask_str),
             max_bits = if(tuple_size(ip) == 4, do: 32, else: 128),
             true <- mask >= 0 and mask <= max_bits do
          {:ok, ip, mask}
        else
          _ -> :error
        end

      [ip_str] ->
        case :inet.parse_address(String.to_charlist(ip_str)) do
          {:ok, ip} -> {:ok, ip, if(tuple_size(ip) == 4, do: 32, else: 128)}
          _ -> :error
        end
    end
  end

  defp ip_in_network?(ip_str, network, mask) do
    case :inet.parse_address(String.to_charlist(ip_str)) do
      {:ok, ip} ->
        ip_int = ip_to_integer(ip)
        net_int = ip_to_integer(network)
        bits = if tuple_size(network) == 4, do: 32, else: 128
        shift = bits - mask
        Bitwise.bsr(ip_int, shift) == Bitwise.bsr(net_int, shift)

      _ ->
        false
    end
  end

  defp ip_to_integer({a, b, c, d}) do
    Bitwise.bsl(a, 24) + Bitwise.bsl(b, 16) + Bitwise.bsl(c, 8) + d
  end

  defp ip_to_integer(ipv6) when tuple_size(ipv6) == 8 do
    ipv6 |> Tuple.to_list() |> Enum.reduce(0, fn seg, acc -> Bitwise.bsl(acc, 16) + seg end)
  end

  defp audit_ip_rejected(api_key, client_ip, tenant_id) do
    PkiPlatformEngine.PlatformAudit.log("api_key_ip_rejected", %{
      target_type: "api_key",
      target_id: api_key.id,
      tenant_id: tenant_id,
      portal: "ra",
      details: %{ip: client_ip, whitelist: api_key.ip_whitelist}
    })
  rescue
    _ -> :ok
  end
end
