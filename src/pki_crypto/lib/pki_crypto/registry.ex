defmodule PkiCrypto.Registry do
  @moduledoc "Maps algorithm name strings to protocol-implementing structs."

  @algorithms %{
    "RSA-4096"  => %PkiCrypto.Signing.RSA4096{},
    "ECC-P256"  => %PkiCrypto.Signing.ECCP256{},
    "ECC-P384"  => %PkiCrypto.Signing.ECCP384{},
    "ECDH-P256" => %PkiCrypto.Kem.ECDHP256{},
  }

  def get(name), do: Map.get(@algorithms, name)

  def signing_algorithms do
    @algorithms
    |> Enum.filter(fn {_, algo} -> PkiCrypto.Algorithm.algorithm_type(algo) == :signing end)
    |> Map.new()
  end

  def kem_algorithms do
    @algorithms
    |> Enum.filter(fn {_, algo} -> PkiCrypto.Algorithm.algorithm_type(algo) == :kem end)
    |> Map.new()
  end

  def all, do: @algorithms
end
