defmodule PkiCrypto.Kem.ECDHP256Test do
  use ExUnit.Case, async: true
  use PkiCrypto.AlgorithmSharedTest, algorithm: %PkiCrypto.Kem.ECDHP256{}

  test "identifier is ECDH-P256" do
    assert PkiCrypto.Algorithm.identifier(%PkiCrypto.Kem.ECDHP256{}) == "ECDH-P256"
  end

  test "algorithm_type is :kem" do
    assert PkiCrypto.Algorithm.algorithm_type(%PkiCrypto.Kem.ECDHP256{}) == :kem
  end

  test "sign operations return :not_supported" do
    algo = %PkiCrypto.Kem.ECDHP256{}
    assert {:error, :not_supported} = PkiCrypto.Algorithm.sign(algo, "key", "data")
    assert {:error, :not_supported} = PkiCrypto.Algorithm.verify(algo, "key", "sig", "data")
  end

  test "shared secret is 32 bytes" do
    algo = %PkiCrypto.Kem.ECDHP256{}
    {:ok, %{public_key: pub, private_key: _priv}} = PkiCrypto.Algorithm.generate_keypair(algo)
    {:ok, {shared_secret, _ct}} = PkiCrypto.Algorithm.kem_encapsulate(algo, pub)
    assert byte_size(shared_secret) == 32
  end
end
