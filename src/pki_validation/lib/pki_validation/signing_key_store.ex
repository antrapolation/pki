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

  @type status :: %{
          loaded: non_neg_integer(),
          failed: non_neg_integer(),
          last_error: atom() | nil,
          healthy: boolean()
        }

  @doc """
  Return an operational status summary for the store.

  Used by /health to report signing key availability. When `failed > 0` the
  store is considered degraded (not healthy).
  """
  @spec status(GenServer.server()) :: status()
  def status(server \\ __MODULE__) do
    GenServer.call(server, :status)
  end

  @doc """
  Test helper: encrypt a private key with the given password using the same
  scheme this module uses for at-rest storage.
  """
  def encrypt_for_test(private_key, password) do
    password_bin = coerce_password(password)
    salt = :crypto.strong_rand_bytes(16)
    key = :crypto.pbkdf2_hmac(:sha256, password_bin, salt, @kdf_iterations, @kdf_key_length)
    iv = :crypto.strong_rand_bytes(12)
    {ct, tag} = :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, private_key, "", true)
    salt <> iv <> tag <> ct
  end

  ## Server callbacks

  @impl true
  def init(opts) do
    password = resolve_password(opts)
    {keys, loaded_count, failed} = load_keys(password)

    Logger.info(
      "SigningKeyStore loaded #{loaded_count} signing keys " <>
        "(#{length(failed)} failed)"
    )

    state = %{
      password: password,
      keys: keys,
      loaded_count: loaded_count,
      failed: failed
    }

    {:ok, state}
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
        if key.key_hash == target_hash do
          {:ok, key, issuer_id}
        end
      end)

    {:reply, result, state}
  end

  def handle_call(:reload, _from, state) do
    {keys, loaded_count, failed} = load_keys(state.password)

    new_state = %{
      state
      | keys: keys,
        loaded_count: loaded_count,
        failed: failed
    }

    {:reply, :ok, new_state}
  end

  def handle_call(:status, _from, state) do
    last_error =
      case state.failed do
        [%{reason: reason} | _] -> reason
        _ -> nil
      end

    status = %{
      loaded: state.loaded_count,
      failed: length(state.failed),
      last_error: last_error,
      healthy: state.failed == []
    }

    {:reply, status, state}
  end

  ## Private helpers

  defp resolve_password(opts) do
    raw =
      Keyword.get(opts, :password) || System.get_env("VALIDATION_SIGNING_KEY_PASSWORD") || ""

    coerce_password(raw)
  end

  # Ensure we always feed a binary into PBKDF2 so a stray charlist (e.g. from
  # a config file) doesn't silently produce a different derived key. Reject
  # anything that isn't clearly a password — silently coercing nil/atom/integer
  # to a string would mask configuration mistakes.
  defp coerce_password(p) when is_binary(p), do: p
  defp coerce_password(p) when is_list(p), do: IO.iodata_to_binary(p)

  defp coerce_password(p) do
    raise ArgumentError,
          "SigningKeyStore password must be a binary or charlist, got: #{inspect(p)}"
  end

  defp load_keys(password) do
    SigningKeyConfig
    |> where([c], c.status == "active")
    |> Repo.all()
    |> Enum.reduce({%{}, 0, []}, fn config, {keys, loaded, failed} ->
      # Resolve the signer FIRST so a row with an unknown algorithm fails
      # fast without doing wasted crypto work.
      with {:ok, signer_mod} <- resolve_signer(config.algorithm),
           {:ok, raw_priv} <- decrypt_private_key(config.encrypted_private_key, password),
           {:ok, decoded_priv} <- decode_private_key(signer_mod, raw_priv),
           {:ok, cert_der} <- decode_cert_pem(config.certificate_pem) do
        entry = %{
          algorithm: config.algorithm,
          signer: signer_mod,
          # `private_key` is now in the signer-specific decoded form. For ECC
          # signers this is still the raw scalar binary (passthrough). For
          # RSA signers this is an `:RSAPrivateKey` record.
          private_key: decoded_priv,
          certificate_der: cert_der,
          # Cache the SHA-1 issuerKeyHash so OCSP lookups by key hash don't
          # have to re-decode + re-hash every cert on every request.
          key_hash: PkiValidation.CertId.issuer_key_hash(cert_der),
          not_after: config.not_after
        }

        {Map.put(keys, config.issuer_key_id, entry), loaded + 1, failed}
      else
        {:error, reason} ->
          Logger.error(
            "Failed to load signing key for issuer #{config.issuer_key_id}: #{inspect(reason)}"
          )

          failure = %{issuer_key_id: config.issuer_key_id, reason: reason}
          # Cap the failed list at the 50 most recent entries to prevent
          # unbounded growth on many-key deployments.
          new_failed = Enum.take([failure | failed], 50)
          {keys, loaded, new_failed}
      end
    end)
  end

  defp resolve_signer(algorithm) do
    case PkiValidation.Crypto.Signer.Registry.fetch(algorithm) do
      {:ok, mod} -> {:ok, mod}
      :error -> {:error, :unknown_algorithm}
    end
  end

  # The Signer behaviour's `decode_private_key/1` callback returns the
  # decoded term directly (not wrapped). ECC modules return the raw scalar
  # binary; RSA modules return a decoded `:RSAPrivateKey` record. We wrap
  # the call in a rescue so an algorithm-specific decode failure (e.g.
  # malformed RSA DER) drops that single key with a clean failure reason
  # rather than crashing the whole GenServer.
  defp decode_private_key(signer_mod, raw_priv) do
    {:ok, signer_mod.decode_private_key(raw_priv)}
  rescue
    _ -> {:error, :private_key_decode_failed}
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
