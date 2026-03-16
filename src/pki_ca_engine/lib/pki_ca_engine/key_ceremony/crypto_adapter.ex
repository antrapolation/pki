defprotocol PkiCaEngine.KeyCeremony.CryptoAdapter do
  @moduledoc """
  Protocol abstracting cryptographic operations for key ceremonies.

  This enables testing without real crypto dependencies. The real implementation
  will delegate to `keyx` + `strap_priv_key_store_provider` once those deps are added.
  """

  @doc "Generate a keypair. Returns {:ok, %{public_key: binary, private_key: binary}}"
  @spec generate_keypair(t(), String.t()) :: {:ok, map()} | {:error, term()}
  def generate_keypair(adapter, algorithm)

  @doc "Split secret into N shares with K threshold. Returns {:ok, shares_list}"
  @spec split_secret(t(), binary(), pos_integer(), pos_integer()) ::
          {:ok, [binary()]} | {:error, term()}
  def split_secret(adapter, secret, k, n)

  @doc "Recover secret from K shares. Returns {:ok, secret}"
  @spec recover_secret(t(), [binary()]) :: {:ok, binary()} | {:error, term()}
  def recover_secret(adapter, shares)
end
