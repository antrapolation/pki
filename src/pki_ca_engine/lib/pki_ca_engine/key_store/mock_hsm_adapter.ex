defmodule PkiCaEngine.KeyStore.MockHsmAdapter do
  @moduledoc """
  In-memory mock HSM for testing and local development.

  Signs using PkiCrypto primitives directly but through the KeyStore
  interface, simulating the HSM signing flow without any PKCS#11 library or
  hardware device. Key material is held in an ETS table that acts as the
  "token object store".

  ## Usage

      # Start the adapter (done automatically by the test setup or supervisor)
      {:ok, _} = MockHsmAdapter.start_link()

      # Generate a key pair — stores private key in ETS, returns public key
      {:ok, pub} = MockHsmAdapter.generate_keypair("ECC-P256")

      # Import an existing private key (DER-encoded)
      :ok = MockHsmAdapter.import_key(issuer_key_id, "ECC-P256", priv_der)

      # Sign via the KeyStore behaviour
      {:ok, signature} = MockHsmAdapter.sign(issuer_key_id, tbs_data)

      # Check availability
      true = MockHsmAdapter.key_available?(issuer_key_id)

  ## Routing

  Issuer keys with `keystore_type: :mock_hsm` are routed here by
  `KeyStore.Dispatcher`.
  """

  @behaviour PkiCaEngine.KeyStore

  use GenServer

  require Logger

  @table :mock_hsm_keys

  # ---------------------------------------------------------------------------
  # GenServer lifecycle
  # ---------------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @impl GenServer
  def init(_opts) do
    # Use a named, public table so any process (callers, tests) can read and write
    # without having to go through the GenServer for every ETS operation.
    # This is intentional for a test/mock adapter — production adapters use PKCS#11.
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :set, :public, read_concurrency: true])
    end

    Logger.debug("MockHsmAdapter started — ETS table #{@table} ready")
    {:ok, %{}}
  end

  # ---------------------------------------------------------------------------
  # Public API (callable without going through Dispatcher)
  # ---------------------------------------------------------------------------

  @doc """
  Generate a keypair for `algorithm`, store the private key in the mock HSM,
  and return the raw public key binary.

  `algorithm` must be a string recognised by `PkiCrypto.Registry`
  (e.g. "ECC-P256", "RSA-2048", "KAZ-SIGN-192").

  Returns `{:ok, public_key_binary}` or `{:error, reason}`.
  """
  @spec generate_keypair(algorithm :: String.t()) :: {:ok, binary()} | {:error, term()}
  def generate_keypair(algorithm) do
    case PkiCrypto.Registry.get(algorithm) do
      nil ->
        {:error, {:unknown_algorithm, algorithm}}

      algo ->
        with {:ok, %{public_key: pub, private_key: priv}} <- PkiCrypto.Algorithm.generate_keypair(algo) do
          key_id = generate_key_id()
          :ets.insert(@table, {key_id, algorithm, priv})
          {:ok, pub, key_id}
        end
    end
  end

  @doc """
  Import an existing DER-encoded private key into the mock HSM store, keyed by
  `issuer_key_id`.  Call this before `sign/2` when you already have the key
  material (e.g. generated outside the mock).
  """
  @spec import_key(issuer_key_id :: binary(), algorithm :: String.t(), private_key_der :: binary()) ::
    :ok | {:error, term()}
  def import_key(issuer_key_id, algorithm, private_key_der) do
    :ets.insert(@table, {issuer_key_id, algorithm, private_key_der})
    :ok
  end

  @doc "Remove a key from the mock store (simulates key destruction)."
  @spec delete_key(issuer_key_id :: binary()) :: :ok
  def delete_key(issuer_key_id) do
    :ets.delete(@table, issuer_key_id)
    :ok
  end

  @doc "Reset the mock HSM — clears all keys. Useful between test cases."
  @spec reset() :: :ok
  def reset do
    :ets.delete_all_objects(@table)
    :ok
  end

  # ---------------------------------------------------------------------------
  # KeyStore behaviour callbacks
  # ---------------------------------------------------------------------------

  @impl PkiCaEngine.KeyStore
  def sign(issuer_key_id, tbs_data) do
    case :ets.lookup(@table, issuer_key_id) do
      [] ->
        {:error, {:key_not_in_mock_hsm, issuer_key_id}}

      [{^issuer_key_id, algorithm, private_key_der}] ->
        do_sign(algorithm, private_key_der, tbs_data)
    end
  end

  @impl PkiCaEngine.KeyStore
  def get_public_key(issuer_key_id) do
    case :ets.lookup(@table, issuer_key_id) do
      [] ->
        {:error, {:key_not_in_mock_hsm, issuer_key_id}}

      [{^issuer_key_id, algorithm, private_key_der}] ->
        extract_public_key(algorithm, private_key_der)
    end
  end

  @impl PkiCaEngine.KeyStore
  def key_available?(issuer_key_id) do
    case :ets.lookup(@table, issuer_key_id) do
      [] -> false
      [_] -> true
    end
  end

  # ---------------------------------------------------------------------------
  # Private helpers
  # ---------------------------------------------------------------------------

  defp do_sign(algorithm, private_key_der, tbs_data) do
    case PkiCrypto.AlgorithmRegistry.by_id(algorithm) do
      {:ok, %{family: family}} when family in [:ml_dsa, :kaz_sign, :slh_dsa] ->
        case PkiCrypto.Registry.get(algorithm) do
          nil  -> {:error, {:unknown_algorithm, algorithm}}
          algo -> PkiCrypto.Algorithm.sign(algo, private_key_der, tbs_data)
        end

      {:ok, %{family: :ecdsa}} ->
        hash = if algorithm == "ECC-P384", do: :sha384, else: :sha256

        try do
          native_key = :public_key.der_decode(:ECPrivateKey, private_key_der)
          {:ok, :public_key.sign(tbs_data, hash, native_key)}
        rescue
          e -> {:error, {:sign_failed, Exception.message(e)}}
        end

      {:ok, %{family: :rsa}} ->
        try do
          native_key = :public_key.der_decode(:RSAPrivateKey, private_key_der)
          {:ok, :public_key.sign(tbs_data, :sha256, native_key)}
        rescue
          e -> {:error, {:sign_failed, Exception.message(e)}}
        end

      :error ->
        # Fall back to PkiCrypto.Registry for algorithms not in AlgorithmRegistry
        case PkiCrypto.Registry.get(algorithm) do
          nil  -> {:error, {:unknown_algorithm, algorithm}}
          algo -> PkiCrypto.Algorithm.sign(algo, private_key_der, tbs_data)
        end
    end
  end

  defp extract_public_key(algorithm, private_key_der) do
    case PkiCrypto.AlgorithmRegistry.by_id(algorithm) do
      {:ok, %{family: :ecdsa}} ->
        try do
          native_key = :public_key.der_decode(:ECPrivateKey, private_key_der)
          params  = elem(native_key, 3)
          pub_raw = elem(native_key, 4)
          {:ok, :public_key.der_encode(:SubjectPublicKeyInfo,
            {:SubjectPublicKeyInfo,
              {:AlgorithmIdentifier, {1, 2, 840, 10045, 2, 1}, params},
              pub_raw})}
        rescue
          _ -> {:error, :cannot_extract_public_key}
        end

      {:ok, %{family: :rsa}} ->
        try do
          priv = :public_key.der_decode(:RSAPrivateKey, private_key_der)
          # RSAPublicKey is the first few fields of RSAPrivateKey
          pub  = {:RSAPublicKey, elem(priv, 2), elem(priv, 3)}
          {:ok, :public_key.der_encode(:RSAPublicKey, pub)}
        rescue
          _ -> {:error, :cannot_extract_public_key}
        end

      _ ->
        # For PQC algorithms, public key extraction from private key DER is
        # algorithm-specific; callers should use the public key returned by
        # generate_keypair/1 or import_key/3 separately.
        {:error, :public_key_not_available_for_algorithm}
    end
  end

  defp generate_key_id do
    :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
  end
end
