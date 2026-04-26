defmodule PkiCaEngine.KeyStore.RemoteHsmAdapter do
  @moduledoc """
  KeyStore adapter for remote PKCS#11 HSMs via WebSocket agent.

  Delegates signing to `PkiCaEngine.HsmGateway`, which forwards requests
  to the connected Go agent over a WebSocket with JSON messages (wire
  format defined in `priv/proto/hsm_gateway.proto`).

  ## Signature verification

  Every signature returned by the agent is verified against the issuer
  key's stored public key before being returned to the caller. A rogue
  or compromised agent cannot inject arbitrary bytes — the adapter
  treats the remote agent as untrusted and validates every response.
  """
  @behaviour PkiCaEngine.KeyStore

  require Logger

  alias PkiMnesia.{Repo, Structs.IssuerKey}
  alias PkiCaEngine.HsmGateway

  @impl true
  def sign(issuer_key_id, tbs_data, opts \\ []) do
    gateway = Keyword.get(opts, :gateway, HsmGateway)
    timeout = Keyword.get(opts, :timeout, 5_000)

    with {:ok, key} <- get_issuer_key(issuer_key_id),
         :ok <- ensure_connected(gateway),
         {:ok, signature} <- request_signature(gateway, key, tbs_data, timeout),
         :ok <- verify_signature(key, tbs_data, signature) do
      {:ok, signature}
    end
  end

  defp ensure_connected(gateway) do
    try do
      if HsmGateway.agent_connected?(gateway), do: :ok, else: {:error, :agent_not_connected}
    catch
      :exit, _ -> {:error, :agent_not_connected}
    end
  end

  defp request_signature(gateway, key, tbs_data, timeout) do
    try do
      HsmGateway.sign_request(
        gateway,
        key.hsm_config["key_label"],
        tbs_data,
        key.algorithm,
        timeout: timeout
      )
    catch
      :exit, _ -> {:error, :agent_not_connected}
    end
  end

  # The agent is untrusted — verify the signature it returned against the
  # issuer's stored public key before accepting. Without this check, a rogue
  # agent can return attacker-chosen bytes that downstream code commits as a
  # valid CA signature.
  defp verify_signature(key, tbs_data, signature) do
    with {:ok, pub_key_der} <- get_public_key_from_key(key),
         {:ok, algo} <- resolve_algorithm(key.algorithm) do
      case PkiCrypto.Algorithm.verify(algo, pub_key_der, signature, tbs_data) do
        :ok ->
          :ok

        {:error, _} = err ->
          Logger.error(
            "HSM agent returned invalid signature for issuer_key #{key.id} (algo=#{key.algorithm}). " <>
              "Rejecting — the agent or gateway may be compromised."
          )

          err

        true ->
          :ok

        false ->
          Logger.error("HSM agent returned invalid signature for issuer_key #{key.id}")
          {:error, :invalid_signature}
      end
    end
  end

  defp get_public_key_from_key(%{certificate_der: nil}), do: {:error, :no_public_key}

  defp get_public_key_from_key(%{certificate_der: der, algorithm: algo_id}) do
    # Parsing path:
    #   Certificate → TBSCertificate → subjectPublicKeyInfo → {algo, pubkey_bytes}
    # Extract the field at index 7 (0-tag, 1-version, 2-serial, 3-sig,
    # 4-issuer, 5-validity, 6-subject, 7-spki, ...).
    #
    # Format the pubkey for the algorithm's verify/4:
    #   RSA verify    — wants DER-encoded SubjectPublicKeyInfo
    #   ECC/PQC verify — wants the raw subjectPublicKey bit-string contents
    try do
      plain_cert = :public_key.der_decode(:Certificate, der)
      tbs = elem(plain_cert, 1)
      spki = elem(tbs, 7)
      {:ok, format_pubkey_for_algorithm(algo_id, spki)}
    rescue
      _ -> {:error, :invalid_certificate}
    end
  end

  defp format_pubkey_for_algorithm(algo_id, spki) when is_binary(algo_id) do
    if String.starts_with?(algo_id, "RSA") do
      :public_key.der_encode(:SubjectPublicKeyInfo, spki)
    else
      # ECC + PQC (ML-DSA, KAZ-SIGN, SLH-DSA) all take raw pubkey bytes.
      elem(spki, 2)
    end
  end

  defp resolve_algorithm(algo_id) do
    cond do
      function_exported?(PkiCaEngine.AlgorithmRegistry, :by_id, 1) ->
        case apply(PkiCaEngine.AlgorithmRegistry, :by_id, [algo_id]) do
          {:ok, algo} -> {:ok, algo}
          _ -> registry_fallback(algo_id)
        end

      true ->
        registry_fallback(algo_id)
    end
  end

  defp registry_fallback(algo_id) do
    case PkiCrypto.Registry.get(algo_id) do
      nil -> {:error, {:unknown_algorithm, algo_id}}
      algo -> {:ok, algo}
    end
  end

  @impl true
  def get_public_key(issuer_key_id) do
    # Remote HSM public keys are stored in the IssuerKey certificate
    case get_issuer_key(issuer_key_id) do
      {:ok, %{certificate_der: nil}} ->
        {:error, :no_certificate}

      {:ok, key} ->
        try do
          cert = :public_key.der_decode(:Certificate, key.certificate_der)
          tbs = elem(cert, 1)
          spki = elem(tbs, 6)
          {:ok, :public_key.der_encode(:SubjectPublicKeyInfo, spki)}
        rescue
          _ -> {:error, :invalid_certificate}
        end

      err ->
        err
    end
  end

  @impl true
  def key_available?(issuer_key_id, opts \\ []) do
    gateway = Keyword.get(opts, :gateway, HsmGateway)

    try do
      case get_issuer_key(issuer_key_id) do
        {:ok, key} ->
          HsmGateway.agent_connected?(gateway) and
            key.hsm_config["key_label"] in HsmGateway.available_keys(gateway) and
            agent_id_matches?(key, gateway)

        _ ->
          false
      end
    catch
      :exit, _ -> false
    end
  end

  # If the key has an expected_agent_id in hsm_config, verify the connected agent
  # matches. Prevents a rogue or misconfigured agent from being used to sign
  # with a key intended for a specific registered agent.
  defp agent_id_matches?(key, gateway) do
    case key.hsm_config["expected_agent_id"] do
      nil -> true
      expected -> HsmGateway.connected_agent_id(gateway) == expected
    end
  end

  @doc """
  Authorize a session for a remote HSM adapter.

  Remote HSM authorization is handled externally by the Go agent.  This shim
  records the auth tokens in the handle so the remote agent can verify them
  when a signing request arrives.  The agent performs the actual PIN challenge.
  """
  @impl true
  def authorize_session(key_id, auth_tokens) do
    {:ok, %{key_id: key_id, auth_tokens: auth_tokens, type: :remote_hsm}}
  end

  # -- Private --

  defp get_issuer_key(issuer_key_id) do
    case Repo.get(IssuerKey, issuer_key_id) do
      {:ok, nil} -> {:error, :issuer_key_not_found}
      {:ok, key} -> {:ok, key}
      {:error, _} = err -> err
    end
  end
end
