defmodule PkiCrypto.Registry do
  @moduledoc "Maps algorithm name strings to protocol-implementing structs."

  @algorithms %{
    # Classical
    "RSA-2048"  => %PkiCrypto.Signing.RSA2048{},
    "RSA-4096"  => %PkiCrypto.Signing.RSA4096{},
    "ECC-P256"  => %PkiCrypto.Signing.ECCP256{},
    "ECC-P384"  => %PkiCrypto.Signing.ECCP384{},
    "ECDH-P256" => %PkiCrypto.Kem.ECDHP256{},
    # KAZ-SIGN (Malaysia PQC) — via NIF
    "KAZ-SIGN-128" => %PkiCrypto.Signing.KazSign128{},
    "KAZ-SIGN-192" => %PkiCrypto.Signing.KazSign192{},
    "KAZ-SIGN-256" => %PkiCrypto.Signing.KazSign256{},
    # ML-DSA (FIPS 204) — via liboqs NIF
    "ML-DSA-44" => %PkiCrypto.Signing.MlDsa44{},
    "ML-DSA-65" => %PkiCrypto.Signing.MlDsa65{},
    "ML-DSA-87" => %PkiCrypto.Signing.MlDsa87{},
    # SLH-DSA SHA2 (FIPS 205) — via liboqs NIF
    "SLH-DSA-SHA2-128f" => %PkiCrypto.Signing.SlhDsaSha2128f{},
    "SLH-DSA-SHA2-128s" => %PkiCrypto.Signing.SlhDsaSha2128s{},
    "SLH-DSA-SHA2-192f" => %PkiCrypto.Signing.SlhDsaSha2192f{},
    "SLH-DSA-SHA2-192s" => %PkiCrypto.Signing.SlhDsaSha2192s{},
    "SLH-DSA-SHA2-256f" => %PkiCrypto.Signing.SlhDsaSha2256f{},
    "SLH-DSA-SHA2-256s" => %PkiCrypto.Signing.SlhDsaSha2256s{},
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
