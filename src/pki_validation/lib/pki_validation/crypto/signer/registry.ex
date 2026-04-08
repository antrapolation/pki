defmodule PkiValidation.Crypto.Signer.Registry do
  @moduledoc """
  Maps algorithm strings from `SigningKeyConfig.algorithm` to concrete
  `PkiValidation.Crypto.Signer` implementations.

  To add a new signer:

    1. Add the algorithm string to
       `PkiValidation.Schema.SigningKeyConfig` `@valid_algorithms`
    2. Create the new module under `PkiValidation.Crypto.Signer.*`
       implementing the `PkiValidation.Crypto.Signer` behaviour
    3. Add one line to `@mapping` below
  """

  alias PkiValidation.Crypto.Signer.{EcdsaP256, EcdsaP384, Rsa2048, Rsa4096}

  @mapping %{
    "ecc_p256" => EcdsaP256,
    "ecc_p384" => EcdsaP384,
    "rsa2048" => Rsa2048,
    "rsa4096" => Rsa4096
  }

  @doc """
  Look up the signer module for a given algorithm string.

  Returns `{:ok, module}` on success or `:error` if the algorithm is
  not registered.
  """
  @spec fetch(String.t()) :: {:ok, module()} | :error
  def fetch(algorithm) when is_binary(algorithm), do: Map.fetch(@mapping, algorithm)
  def fetch(_), do: :error
end
