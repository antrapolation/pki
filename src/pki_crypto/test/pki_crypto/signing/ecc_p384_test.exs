defmodule PkiCrypto.Signing.ECCP384Test do
  use ExUnit.Case, async: true
  use PkiCrypto.AlgorithmSharedTest, algorithm: %PkiCrypto.Signing.ECCP384{}

  test "identifier is ECC-P384" do
    assert PkiCrypto.Algorithm.identifier(%PkiCrypto.Signing.ECCP384{}) == "ECC-P384"
  end

  test "algorithm_type is :signing" do
    assert PkiCrypto.Algorithm.algorithm_type(%PkiCrypto.Signing.ECCP384{}) == :signing
  end

  test "KEM operations return :not_supported" do
    algo = %PkiCrypto.Signing.ECCP384{}
    assert {:error, :not_supported} = PkiCrypto.Algorithm.kem_encapsulate(algo, "key")
    assert {:error, :not_supported} = PkiCrypto.Algorithm.kem_decapsulate(algo, "key", "ct")
  end

  test "private key is DER-decodable EC key" do
    algo = %PkiCrypto.Signing.ECCP384{}
    {:ok, %{private_key: priv}} = PkiCrypto.Algorithm.generate_keypair(algo)
    assert {:ECPrivateKey, _, _, _, _, _} = :public_key.der_decode(:ECPrivateKey, priv)
  end
end
