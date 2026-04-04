defmodule PkiRaEngine.DcvVerifier do
  @moduledoc "Performs HTTP-01 and DNS-01 domain control verification."

  require Logger

  @http_timeout 10_000
  @max_redirects 3

  def check_http_01(domain, token, token_value) do
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
  rescue
    e -> {:error, "HTTP check failed: #{Exception.message(e)}"}
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
