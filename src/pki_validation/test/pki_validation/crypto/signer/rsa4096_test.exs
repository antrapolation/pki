defmodule PkiValidation.Crypto.Signer.Rsa4096Test do
  use ExUnit.Case, async: true

  alias PkiValidation.Crypto.Signer.Rsa4096

  @moduletag timeout: 60_000

  setup do
    rsa_priv_record = :public_key.generate_key({:rsa, 4096, 65537})
    rsa_priv_der = :public_key.der_encode(:RSAPrivateKey, rsa_priv_record)
    {:ok, rsa_priv_record: rsa_priv_record, rsa_priv_der: rsa_priv_der}
  end

  test "decode_private_key/1 decodes DER into :RSAPrivateKey record", %{
    rsa_priv_der: der,
    rsa_priv_record: expected
  } do
    assert Rsa4096.decode_private_key(der) == expected
  end

  test "algorithm_identifier_der/0 returns sha256WithRSAEncryption DER" do
    assert Rsa4096.algorithm_identifier_der() ==
             <<0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05,
               0x00>>
  end

  test "algorithm_identifier_record/0 returns the matching Erlang record" do
    assert Rsa4096.algorithm_identifier_record() ==
             {:AlgorithmIdentifier, {1, 2, 840, 113_549, 1, 1, 11}, <<5, 0>>}
  end

  test "sign/2 produces a signature verifiable with RSA public key", %{
    rsa_priv_record: rsa_priv_record,
    rsa_priv_der: der
  } do
    tbs = "rsa-4096 test message"
    decoded = Rsa4096.decode_private_key(der)
    signature = Rsa4096.sign(tbs, decoded)

    assert is_binary(signature)

    modulus = elem(rsa_priv_record, 2)
    public_exponent = elem(rsa_priv_record, 3)
    rsa_pub = {:RSAPublicKey, modulus, public_exponent}

    assert :public_key.verify(tbs, :sha256, signature, rsa_pub)
  end
end
