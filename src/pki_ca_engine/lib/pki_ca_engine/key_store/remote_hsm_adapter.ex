defmodule PkiCaEngine.KeyStore.RemoteHsmAdapter do
  @moduledoc """
  KeyStore adapter for remote PKCS#11 HSMs via WebSocket agent.

  Delegates signing to `PkiCaEngine.HsmGateway`, which forwards requests
  to the connected Go agent over a WebSocket with JSON messages (wire
  format defined in `priv/proto/hsm_gateway.proto`).
  """
  @behaviour PkiCaEngine.KeyStore

  alias PkiMnesia.{Repo, Structs.IssuerKey}
  alias PkiCaEngine.HsmGateway

  @impl true
  def sign(issuer_key_id, tbs_data, opts \\ []) do
    gateway = Keyword.get(opts, :gateway, HsmGateway)
    timeout = Keyword.get(opts, :timeout, 5_000)

    with {:ok, key} <- get_issuer_key(issuer_key_id) do
      try do
        if HsmGateway.agent_connected?(gateway) do
          HsmGateway.sign_request(
            gateway,
            key.hsm_config["key_label"],
            tbs_data,
            key.algorithm,
            timeout: timeout
          )
        else
          {:error, :agent_not_connected}
        end
      catch
        :exit, _ -> {:error, :agent_not_connected}
      end
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
            key.hsm_config["key_label"] in HsmGateway.available_keys(gateway)

        _ ->
          false
      end
    catch
      :exit, _ -> false
    end
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
