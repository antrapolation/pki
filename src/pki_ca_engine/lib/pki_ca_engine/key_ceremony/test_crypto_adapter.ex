defmodule PkiCaEngine.KeyCeremony.TestCryptoAdapter do
  @moduledoc """
  Test/mock implementation of CryptoAdapter protocol.

  Uses simple deterministic splitting for testing purposes.
  NOT suitable for production use.
  """
  defstruct []
end

defimpl PkiCaEngine.KeyCeremony.CryptoAdapter,
  for: PkiCaEngine.KeyCeremony.TestCryptoAdapter do
  def generate_keypair(_adapter, _algorithm) do
    {:ok,
     %{
       public_key: :crypto.strong_rand_bytes(32),
       private_key: :crypto.strong_rand_bytes(32)
     }}
  end

  def split_secret(_adapter, secret, k, n) when k <= n do
    # Simple test split: each share is the index byte prepended to the secret
    shares = for i <- 1..n, do: <<i>> <> secret
    {:ok, shares}
  end

  def recover_secret(_adapter, [share | _]) do
    # Simple test recover: strip the index byte
    <<_index, secret::binary>> = share
    {:ok, secret}
  end
end
