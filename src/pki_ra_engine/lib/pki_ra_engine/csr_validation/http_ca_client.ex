defmodule PkiRaEngine.CsrValidation.HttpCaClient do
  @moduledoc """
  HTTP-based CA client that forwards CSR signing requests to the CA Engine
  over its internal REST API.

  Expects the following application config:

      config :pki_ra_engine, :ca_engine_url, "http://localhost:4001"
      config :pki_ra_engine, :internal_api_secret, "secret"

  The CA Engine must be running and reachable at the configured URL with
  a matching `INTERNAL_API_SECRET`.
  """

  @behaviour PkiRaEngine.CaClient

  require Logger

  @sign_path "/api/v1/certificates/sign"

  @doc """
  Sign a certificate by forwarding the CSR PEM to the CA Engine.

  `cert_profile` is expected to be a map with at least an `:id` key
  (the cert profile ID from the RA side).

  Returns `{:ok, %{serial_number: serial}}` on success, or `{:error, reason}`.
  """
  @impl true
  @spec sign_certificate(String.t(), String.t(), String.t(), map()) :: {:ok, map()} | {:error, term()}
  def sign_certificate(_tenant_id, _issuer_key_id, csr_pem, cert_profile) do
    ca_url = ca_engine_url()
    secret = internal_api_secret()

    if is_nil(ca_url) or ca_url == "" do
      {:error, :ca_engine_url_not_configured}
    else
      do_sign(ca_url, secret, csr_pem, cert_profile)
    end
  end

  # ── Private ─────────────────────────────────────────────────────────

  defp do_sign(ca_url, secret, csr_pem, cert_profile) do
    url = String.trim_trailing(ca_url, "/") <> @sign_path

    body = build_request_body(csr_pem, cert_profile)
    headers = build_headers(secret)

    case Req.post(url, json: body, headers: headers, receive_timeout: 30_000) do
      {:ok, %Req.Response{status: status, body: resp_body}} when status in [200, 201] ->
        parse_success_response(resp_body)

      {:ok, %Req.Response{status: status, body: resp_body}} ->
        reason = extract_error(resp_body)
        Logger.error("CA Engine signing failed (HTTP #{status}): #{inspect(reason)}")
        {:error, {:ca_signing_failed, status, reason}}

      {:error, exception} ->
        Logger.error("CA Engine request failed: #{inspect(exception)}")
        {:error, {:ca_engine_unreachable, exception}}
    end
  end

  defp build_request_body(csr_pem, cert_profile) do
    body = %{
      "csr_pem" => csr_pem,
      "issuer_key_id" => resolve_issuer_key_id(cert_profile)
    }

    profile_data = build_cert_profile(cert_profile)

    if map_size(profile_data) > 0 do
      Map.put(body, "cert_profile", profile_data)
    else
      body
    end
  end

  defp build_cert_profile(cert_profile) do
    %{}
    |> maybe_put("id", Map.get(cert_profile, :id) || Map.get(cert_profile, "id"))
    |> maybe_put("validity_days", Map.get(cert_profile, :validity_days) || Map.get(cert_profile, "validity_days"))
    |> maybe_put("subject_dn", Map.get(cert_profile, :subject_dn) || Map.get(cert_profile, "subject_dn"))
  end

  defp resolve_issuer_key_id(cert_profile) do
    # First check if the profile specifies an issuer_key_id directly
    issuer_key_id =
      Map.get(cert_profile, :issuer_key_id) ||
        Map.get(cert_profile, "issuer_key_id")

    # Fall back to application config
    issuer_key_id || Application.get_env(:pki_ra_engine, :default_issuer_key_id)
  end

  defp build_headers(secret) when is_binary(secret) and secret != "" do
    [{"authorization", "Bearer #{secret}"}]
  end

  defp build_headers(_), do: []

  defp parse_success_response(%{"serial_number" => serial} = resp) do
    {:ok, %{
      serial_number: serial,
      cert_pem: Map.get(resp, "cert_pem"),
      subject_dn: Map.get(resp, "subject_dn"),
      not_before: Map.get(resp, "not_before"),
      not_after: Map.get(resp, "not_after")
    }}
  end

  defp parse_success_response(resp) do
    {:error, {:unexpected_response, resp}}
  end

  defp extract_error(%{"message" => msg}), do: msg
  defp extract_error(%{"error" => err}), do: err
  defp extract_error(other), do: other

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  @doc "Fetches active issuer keys from leaf CA instances."
  def list_leaf_issuer_keys do
    ca_url = ca_engine_url()
    secret = internal_api_secret()

    if is_nil(ca_url) or ca_url == "" do
      {:error, :ca_engine_url_not_configured}
    else
      url = String.trim_trailing(ca_url, "/") <> "/api/v1/issuer-keys?leaf_only=true"
      headers = if secret && secret != "", do: [{"authorization", "Bearer #{secret}"}], else: []

      case Req.get(url, headers: headers, receive_timeout: 10_000) do
        {:ok, %Req.Response{status: 200, body: body}} -> {:ok, body}
        {:ok, %Req.Response{status: status, body: body}} ->
          {:error, {:ca_engine_error, status, extract_error(body)}}
        {:error, reason} -> {:error, {:ca_engine_unreachable, reason}}
      end
    end
  end

  defp ca_engine_url do
    # Check CaEngineConfig GenServer first, fall back to app env
    case PkiRaEngine.CaEngineConfig.get(:ca_engine_url) do
      {:ok, url} when is_binary(url) and url != "" -> url
      _ -> Application.get_env(:pki_ra_engine, :ca_engine_url)
    end
  rescue
    # CaEngineConfig may not be running in all contexts
    _ -> Application.get_env(:pki_ra_engine, :ca_engine_url)
  end

  defp internal_api_secret do
    Application.get_env(:pki_ra_engine, :internal_api_secret)
  end
end
