defmodule PkiCaEngine.KeyStore.SoftwareAdapter do
  @moduledoc """
  KeyStore adapter for software keystores.

  Wraps the existing KeyActivation GenServer. The threshold ceremony
  activation flow is unchanged -- this adapter just bridges the new
  KeyStore behaviour to the existing signing path.
  """
  @behaviour PkiCaEngine.KeyStore

  alias PkiMnesia.{Repo, Structs.IssuerKey}
  alias PkiCaEngine.KeyActivation

  @impl true
  def sign(issuer_key_id, tbs_data, opts \\ []) do
    activation_server = Keyword.get(opts, :activation_server, KeyActivation)

    with {:ok, key} <- get_issuer_key(issuer_key_id),
         {:ok, private_key_der} <- KeyActivation.get_active_key(activation_server, issuer_key_id) do
      do_sign(key.algorithm, private_key_der, tbs_data)
    end
  end

  @impl true
  def get_public_key(issuer_key_id) do
    case get_issuer_key(issuer_key_id) do
      {:ok, %{certificate_der: nil}} -> {:error, :no_certificate}
      {:ok, key} -> extract_public_key(key.certificate_der)
      err -> err
    end
  end

  @impl true
  def key_available?(issuer_key_id, opts \\ []) do
    activation_server = Keyword.get(opts, :activation_server, KeyActivation)
    KeyActivation.is_active?(activation_server, issuer_key_id)
  end

  @doc """
  Get the raw private key DER bytes from KeyActivation.

  Used by CertificateSigning for X.509 certificate assembly via
  `PkiCrypto.X509Builder.sign_tbs` (software path only). HSM paths
  do not need raw key access.
  """
  def get_raw_key(issuer_key_id, opts \\ []) do
    activation_server = Keyword.get(opts, :activation_server, KeyActivation)
    KeyActivation.get_active_key(activation_server, issuer_key_id)
  end

  @doc """
  Backward-compatible session authorization for software keystores.

  For software keys the auth tokens are the custodians' plaintext passwords
  used during the threshold ceremony.  The "session handle" is the first token
  (the reconstructed key material or password) so that existing callers that
  receive the handle can still use it directly.

  Returns `{:ok, %{key_id: key_id, key_material: first_token, type: :software}}`.
  """
  @impl true
  def authorize_session(key_id, auth_tokens) do
    {:ok, %{key_id: key_id, key_material: List.first(auth_tokens), type: :software}}
  end

  # -- Private --

  defp get_issuer_key(issuer_key_id) do
    case Repo.get(IssuerKey, issuer_key_id) do
      {:ok, nil} -> {:error, :issuer_key_not_found}
      {:ok, key} -> {:ok, key}
      {:error, _} = err -> err
    end
  end

  defp do_sign(algorithm, private_key_der, tbs_data) do
    case PkiCrypto.AlgorithmRegistry.by_id(algorithm) do
      {:ok, %{family: family}} when family in [:ml_dsa, :kaz_sign, :slh_dsa] ->
        case PkiCrypto.Registry.get(algorithm) do
          nil -> {:error, {:unknown_algorithm, algorithm}}
          algo -> PkiCrypto.Algorithm.sign(algo, private_key_der, tbs_data)
        end

      {:ok, %{family: :ecdsa}} ->
        hash = if algorithm == "ECC-P384", do: :sha384, else: :sha256
        native_key = :public_key.der_decode(:ECPrivateKey, private_key_der)
        {:ok, :public_key.sign(tbs_data, hash, native_key)}

      {:ok, %{family: :rsa}} ->
        native_key = :public_key.der_decode(:RSAPrivateKey, private_key_der)
        {:ok, :public_key.sign(tbs_data, :sha256, native_key)}

      :error ->
        {:error, {:unknown_algorithm, algorithm}}
    end
  end

  defp extract_public_key(cert_der) do
    try do
      cert = :public_key.der_decode(:Certificate, cert_der)
      tbs = elem(cert, 1)
      spki = elem(tbs, 6)
      {:ok, :public_key.der_encode(:SubjectPublicKeyInfo, spki)}
    rescue
      _ -> {:error, :invalid_certificate}
    end
  end
end
