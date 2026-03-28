defmodule PkiCrypto.Signing.RSA4096Test do
  use ExUnit.Case, async: true
  use PkiCrypto.AlgorithmSharedTest, algorithm: %PkiCrypto.Signing.RSA4096{}

  test "identifier is RSA-4096" do
    assert PkiCrypto.Algorithm.identifier(%PkiCrypto.Signing.RSA4096{}) == "RSA-4096"
  end

  test "algorithm_type is :signing" do
    assert PkiCrypto.Algorithm.algorithm_type(%PkiCrypto.Signing.RSA4096{}) == :signing
  end

  test "KEM operations return :not_supported" do
    algo = %PkiCrypto.Signing.RSA4096{}
    assert {:error, :not_supported} = PkiCrypto.Algorithm.kem_encapsulate(algo, "key")
    assert {:error, :not_supported} = PkiCrypto.Algorithm.kem_decapsulate(algo, "key", "ct")
  end

  test "private key is DER-encoded RSA" do
    algo = %PkiCrypto.Signing.RSA4096{}
    {:ok, %{private_key: priv}} = PkiCrypto.Algorithm.generate_keypair(algo)
    assert {:RSAPrivateKey, _, _, _, _, _, _, _, _, _, _} = :public_key.der_decode(:RSAPrivateKey, priv)
  end
end
