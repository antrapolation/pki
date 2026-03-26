defmodule PkiCrypto.Signing.ECCP256Test do
  use ExUnit.Case, async: true
  use PkiCrypto.AlgorithmSharedTest, algorithm: %PkiCrypto.Signing.ECCP256{}

  test "identifier is ECC-P256" do
    assert PkiCrypto.Algorithm.identifier(%PkiCrypto.Signing.ECCP256{}) == "ECC-P256"
  end

  test "algorithm_type is :signing" do
    assert PkiCrypto.Algorithm.algorithm_type(%PkiCrypto.Signing.ECCP256{}) == :signing
  end

  test "KEM operations return :not_supported" do
    algo = %PkiCrypto.Signing.ECCP256{}
    assert {:error, :not_supported} = PkiCrypto.Algorithm.kem_encapsulate(algo, "key")
    assert {:error, :not_supported} = PkiCrypto.Algorithm.kem_decapsulate(algo, "key", "ct")
  end

  test "private key is DER-decodable EC key" do
    algo = %PkiCrypto.Signing.ECCP256{}
    {:ok, %{private_key: priv}} = PkiCrypto.Algorithm.generate_keypair(algo)
    assert {:ECPrivateKey, _, _, _, _, _} = :public_key.der_decode(:ECPrivateKey, priv)
  end
end
