defmodule PkiOqsNif do
  @moduledoc """
  Elixir NIF bindings for liboqs post-quantum signature algorithms.

  Supports:
  - ML-DSA-44, ML-DSA-65, ML-DSA-87 (FIPS 204)
  - SLH-DSA-SHA2-128f/128s, 192f/192s, 256f/256s (FIPS 205)

  ## Usage

      {:ok, %{public_key: pk, private_key: sk}} = PkiOqsNif.keygen("ML-DSA-65")
      {:ok, signature} = PkiOqsNif.sign("ML-DSA-65", sk, "message")
      :ok = PkiOqsNif.verify("ML-DSA-65", pk, signature, "message")

  """

  @on_load :load_nif

  @doc false
  def load_nif do
    nif_path = :filename.join(:code.priv_dir(:pki_oqs_nif), ~c"oqs_nif")
    :erlang.load_nif(nif_path, 0)
  end

  @doc """
  Generate a keypair for the given algorithm.

  Returns `{:ok, %{public_key: binary, private_key: binary}}` or `{:error, reason}`.
  """
  @spec keygen(String.t()) :: {:ok, %{public_key: binary(), private_key: binary()}} | {:error, atom()}
  def keygen(_algorithm), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Sign a message with the given algorithm and private key.

  Returns `{:ok, signature}` or `{:error, reason}`.
  """
  @spec sign(String.t(), binary(), binary()) :: {:ok, binary()} | {:error, atom()}
  def sign(_algorithm, _private_key, _message), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Verify a signature against a message with the given algorithm and public key.

  Returns `:ok` or `{:error, :invalid_signature}`.
  """
  @spec verify(String.t(), binary(), binary(), binary()) :: :ok | {:error, atom()}
  def verify(_algorithm, _public_key, _signature, _message), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  List all supported algorithm names.
  """
  def supported_algorithms do
    [
      "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
      "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-128s",
      "SLH-DSA-SHA2-192f", "SLH-DSA-SHA2-192s",
      "SLH-DSA-SHA2-256f", "SLH-DSA-SHA2-256s"
    ]
  end
end
