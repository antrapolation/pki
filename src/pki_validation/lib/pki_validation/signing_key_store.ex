defmodule PkiValidation.SigningKeyStore do
  @moduledoc """
  GenServer holding decrypted OCSP/CRL signing keys per issuer.

  On startup, loads all `SigningKeyConfig` records with status = "active",
  decrypts the private keys using the activation password, and stores them
  in process state for fast lookup.

  The activation password is sourced from (in order):
  1. The `:password` option passed to `start_link/1`
  2. `VALIDATION_SIGNING_KEY_PASSWORD` environment variable
  3. Empty string (for tests/dev with empty-password keys)
  """

  use GenServer
  require Logger

  alias PkiValidation.Repo
  alias PkiValidation.Schema.SigningKeyConfig
  import Ecto.Query

  # Matches the pki_crypto KDF defaults — 100k iterations is enough for a server-held secret
  @kdf_iterations 100_000
  @kdf_key_length 32

  ## Client API

  def start_link(opts) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc "Look up a decrypted signing key by issuer_key_id."
  def get(server \\ __MODULE__, issuer_key_id) do
    GenServer.call(server, {:get, issuer_key_id})
  end

  @doc "Look up a signing key by the SHA-1 hash of its public key BIT STRING."
  def find_by_key_hash(server \\ __MODULE__, target_hash) do
    GenServer.call(server, {:find_by_key_hash, target_hash})
  end

  @doc "Reload all active signing keys from the database."
  def reload(server \\ __MODULE__) do
    GenServer.call(server, :reload)
  end

  @doc """
  Test helper: encrypt a private key with the given password using the same
  scheme this module uses for at-rest storage.
  """
  def encrypt_for_test(private_key, password) do
    salt = :crypto.strong_rand_bytes(16)
    key = :crypto.pbkdf2_hmac(:sha256, password, salt, @kdf_iterations, @kdf_key_length)
    iv = :crypto.strong_rand_bytes(12)
    {ct, tag} = :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, private_key, "", true)
    salt <> iv <> tag <> ct
  end

  ## Server callbacks

  @impl true
  def init(opts) do
    password = resolve_password(opts)
    keys = load_keys(password)
    Logger.info("SigningKeyStore loaded #{map_size(keys)} signing keys")
    {:ok, %{password: password, keys: keys}}
  end

  @impl true
  def handle_call({:get, issuer_key_id}, _from, state) do
    case Map.get(state.keys, issuer_key_id) do
      nil -> {:reply, :not_found, state}
      key -> {:reply, {:ok, key}, state}
    end
  end

  def handle_call({:find_by_key_hash, target_hash}, _from, state) do
    result =
      Enum.find_value(state.keys, :not_found, fn {issuer_id, key} ->
        cond do
          is_nil(key.certificate_der) ->
            nil

          PkiValidation.CertId.issuer_key_hash(key.certificate_der) == target_hash ->
            {:ok, key, issuer_id}

          true ->
            nil
        end
      end)

    {:reply, result, state}
  end

  def handle_call(:reload, _from, state) do
    {:reply, :ok, %{state | keys: load_keys(state.password)}}
  end

  ## Private helpers

  defp resolve_password(opts) do
    Keyword.get(opts, :password) || System.get_env("VALIDATION_SIGNING_KEY_PASSWORD") || ""
  end

  defp load_keys(password) do
    SigningKeyConfig
    |> where([c], c.status == "active")
    |> Repo.all()
    |> Enum.reduce(%{}, fn config, acc ->
      with {:ok, priv} <- decrypt_private_key(config.encrypted_private_key, password),
           {:ok, cert_der} <- decode_cert_pem(config.certificate_pem) do
        Map.put(acc, config.issuer_key_id, %{
          algorithm: config.algorithm,
          private_key: priv,
          certificate_der: cert_der,
          not_after: config.not_after
        })
      else
        {:error, reason} ->
          Logger.error(
            "Failed to load signing key for issuer #{config.issuer_key_id}: #{inspect(reason)}"
          )

          acc
      end
    end)
  end

  defp decrypt_private_key(
         <<salt::binary-size(16), iv::binary-size(12), tag::binary-size(16), ct::binary>>,
         password
       ) do
    key = :crypto.pbkdf2_hmac(:sha256, password, salt, @kdf_iterations, @kdf_key_length)

    case :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, ct, "", tag, false) do
      plain when is_binary(plain) -> {:ok, plain}
      :error -> {:error, :decryption_failed}
    end
  rescue
    _ -> {:error, :malformed_ciphertext}
  end

  defp decrypt_private_key(_, _), do: {:error, :malformed_ciphertext}

  defp decode_cert_pem(pem) when is_binary(pem) do
    case :public_key.pem_decode(pem) do
      [{:Certificate, der, _} | _] -> {:ok, der}
      _ -> {:error, :invalid_cert_pem}
    end
  end

  defp decode_cert_pem(_), do: {:error, :invalid_cert_pem}
end
