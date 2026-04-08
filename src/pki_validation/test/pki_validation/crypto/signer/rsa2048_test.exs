defmodule PkiValidation.Crypto.Signer.Rsa2048Test do
  use ExUnit.Case, async: true

  alias PkiValidation.Crypto.Signer.Rsa2048

  setup do
    rsa_priv_record = :public_key.generate_key({:rsa, 2048, 65537})
    rsa_priv_der = :public_key.der_encode(:RSAPrivateKey, rsa_priv_record)

    {:ok, rsa_priv_record: rsa_priv_record, rsa_priv_der: rsa_priv_der}
  end

  test "decode_private_key/1 decodes the DER form into the :RSAPrivateKey record", %{
    rsa_priv_der: der,
    rsa_priv_record: expected
  } do
    assert Rsa2048.decode_private_key(der) == expected
  end

  test "algorithm_identifier_der/0 returns the RFC 4055 sha256WithRSAEncryption DER" do
    # sha256WithRSAEncryption OID is 1.2.840.113549.1.1.11
    # AlgorithmIdentifier has NULL params for RSA (05 00)
    # SEQUENCE { OID 1.2.840.113549.1.1.11, NULL }
    # = 30 0D 06 09 2A 86 48 86 F7 0D 01 01 0B 05 00
    assert Rsa2048.algorithm_identifier_der() ==
             <<0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05,
               0x00>>
  end

  test "algorithm_identifier_record/0 returns the matching Erlang record" do
    # RSA AlgorithmIdentifier params are NULL (encoded as <<5, 0>>) per
    # RFC 4055.
    assert Rsa2048.algorithm_identifier_record() ==
             {:AlgorithmIdentifier, {1, 2, 840, 113_549, 1, 1, 11}, <<5, 0>>}
  end

  test "sign/2 produces a signature verifiable with the RSA public key", %{
    rsa_priv_record: rsa_priv_record,
    rsa_priv_der: der
  } do
    tbs = "rsa-2048 test message"

    # SigningKeyStore would have called decode_private_key/1 at load time
    decoded = Rsa2048.decode_private_key(der)
    signature = Rsa2048.sign(tbs, decoded)

    assert is_binary(signature)

    # Extract the public key from the private record.
    # The OTP :RSAPrivateKey record shape is
    # {:RSAPrivateKey, version, modulus, publicExponent, privateExponent,
    #  prime1, prime2, exponent1, exponent2, coefficient, otherPrimeInfos}
    # — 11 fields, so we match the first three we care about.
    modulus = elem(rsa_priv_record, 2)
    public_exponent = elem(rsa_priv_record, 3)
    rsa_pub = {:RSAPublicKey, modulus, public_exponent}

    assert :public_key.verify(tbs, :sha256, signature, rsa_pub)
  end
end
