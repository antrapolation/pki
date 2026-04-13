defmodule PkiRaEngine.DcvVerifier do
  @moduledoc "Performs HTTP-01 and DNS-01 domain control verification."

  require Logger

  @http_timeout 10_000
  @max_redirects 3

  def check_http_01(domain, token, token_value) do
    with :ok <- validate_domain(domain) do
      url = "http://#{domain}/.well-known/pki-validation/#{token}"

      case Req.get(url, receive_timeout: @http_timeout, max_redirects: @max_redirects) do
        {:ok, %{status: 200, body: body}} when is_binary(body) ->
          if String.contains?(body, token_value) do
            :ok
          else
            {:error, "Token value not found in response body"}
          end

        {:ok, %{status: status}} ->
          {:error, "HTTP #{status}"}

        {:error, reason} ->
          {:error, "Connection failed: #{inspect(reason)}"}
      end
    end
  rescue
    e -> {:error, "HTTP check failed: #{Exception.message(e)}"}
  end

  defp validate_domain(domain) do
    cond do
      String.contains?(domain, ["localhost", "127.0.0.1", "::1", "0.0.0.0"]) ->
        {:error, "blocked domain: internal address"}

      String.match?(domain, ~r/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) ->
        case :inet.parse_address(String.to_charlist(domain)) do
          {:ok, {10, _, _, _}} -> {:error, "blocked domain: private IP"}
          {:ok, {172, b, _, _}} when b >= 16 and b <= 31 -> {:error, "blocked domain: private IP"}
          {:ok, {192, 168, _, _}} -> {:error, "blocked domain: private IP"}
          {:ok, {169, 254, _, _}} -> {:error, "blocked domain: link-local IP"}
          {:ok, {127, _, _, _}} -> {:error, "blocked domain: loopback"}
          _ -> :ok
        end

      true ->
        case :inet.getaddr(String.to_charlist(domain), :inet) do
          {:ok, {10, _, _, _}} -> {:error, "blocked domain: resolves to private IP"}
          {:ok, {172, b, _, _}} when b >= 16 and b <= 31 -> {:error, "blocked domain: resolves to private IP"}
          {:ok, {192, 168, _, _}} -> {:error, "blocked domain: resolves to private IP"}
          {:ok, {169, 254, _, _}} -> {:error, "blocked domain: resolves to link-local IP"}
          {:ok, {127, _, _, _}} -> {:error, "blocked domain: resolves to loopback"}
          {:ok, _} -> :ok
          {:error, _} -> :ok
        end
    end
  end

  def check_dns_01(domain, token_value) do
    lookup_name = ~c"_pki-validation.#{domain}"

    case :inet_res.lookup(lookup_name, :in, :txt) do
      [] ->
        {:error, "No TXT records found for _pki-validation.#{domain}"}

      records ->
        found =
          Enum.any?(records, fn txt_parts ->
            txt = txt_parts |> Enum.map(&to_string/1) |> Enum.join()
            String.contains?(txt, token_value)
          end)

        if found, do: :ok, else: {:error, "Token value not found in TXT records"}
    end
  rescue
    e -> {:error, "DNS check failed: #{Exception.message(e)}"}
  end
end
