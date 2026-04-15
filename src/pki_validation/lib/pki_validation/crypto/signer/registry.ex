defmodule PkiValidation.Crypto.Signer.Registry do
  @moduledoc """
  Maps algorithm strings from `SigningKeyConfig.algorithm` to concrete
  `PkiValidation.Crypto.Signer` implementations.

  To add a new signer:

    1. Create the new module under `PkiValidation.Crypto.Signer.*`
       implementing the `PkiValidation.Crypto.Signer` behaviour
    2. Add one line to `@mapping` below

  `SigningKeyConfig` looks up `algorithms/0` at runtime, so the schema
  automatically accepts any algorithm added here without further changes.
  """

  alias PkiValidation.Crypto.Signer.{
    EcdsaP256,
    EcdsaP384,
    Rsa2048,
    Rsa4096,
    MlDsa44,
    MlDsa65,
    MlDsa87,
    KazSign128,
    KazSign192,
    KazSign256
  }

  @mapping %{
    "ecc_p256" => EcdsaP256,
    "ecc_p384" => EcdsaP384,
    "rsa2048" => Rsa2048,
    "rsa4096" => Rsa4096,
    "ml_dsa_44" => MlDsa44,
    "ml_dsa_65" => MlDsa65,
    "ml_dsa_87" => MlDsa87,
    "kaz_sign_128" => KazSign128,
    "kaz_sign_192" => KazSign192,
    "kaz_sign_256" => KazSign256
  }

  @algorithms Map.keys(@mapping)

  @doc """
  Look up the signer module for a given algorithm string.

  Returns `{:ok, module}` on success or `:error` if the algorithm is
  not registered.
  """
  @spec fetch(String.t()) :: {:ok, module()} | :error
  def fetch(algorithm) when is_binary(algorithm), do: Map.fetch(@mapping, algorithm)
  def fetch(_), do: :error

  @doc """
  Return the list of algorithm strings with a registered signer.

  This is the single source of truth for which algorithm strings the
  validation service can sign with. `SigningKeyConfig` calls this
  function at runtime inside its changeset, so the schema and the
  dispatch table cannot drift apart — adding an entry to `@mapping`
  automatically extends the schema's allowed set.
  """
  @spec algorithms() :: [String.t()]
  def algorithms, do: @algorithms
end
