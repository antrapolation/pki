defmodule PkiValidation.Crypto.Signer.EcdsaP384Test do
  use ExUnit.Case, async: true

  alias PkiValidation.Crypto.Signer.EcdsaP384

  setup do
    {pub_point, priv_scalar} = :crypto.generate_key(:ecdh, :secp384r1)
    {:ok, pub_point: pub_point, priv_scalar: priv_scalar}
  end

  test "decode_private_key/1 passes raw ECC scalar bytes through unchanged", %{priv_scalar: priv} do
    assert EcdsaP384.decode_private_key(priv) == priv
  end

  test "algorithm_identifier_der/0 returns the RFC 5754 ecdsa-with-SHA384 DER" do
    # ecdsa-with-SHA384 OID is 1.2.840.10045.4.3.3
    # SEQUENCE { OID 1.2.840.10045.4.3.3 }
    # = 30 0A 06 08 2A 86 48 CE 3D 04 03 03
    assert EcdsaP384.algorithm_identifier_der() ==
             <<0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03>>
  end

  test "algorithm_identifier_record/0 returns the matching Erlang record" do
    assert EcdsaP384.algorithm_identifier_record() ==
             {:AlgorithmIdentifier, {1, 2, 840, 10045, 4, 3, 3}, :asn1_NOVALUE}
  end

  test "sign/2 produces a signature verifiable with :public_key.verify/4", %{
    pub_point: pub,
    priv_scalar: priv
  } do
    tbs = "p-384 test message"

    signature = EcdsaP384.sign(tbs, EcdsaP384.decode_private_key(priv))

    p384_oid = {1, 3, 132, 0, 34}

    assert :public_key.verify(
             tbs,
             :sha384,
             signature,
             {{:ECPoint, pub}, {:namedCurve, p384_oid}}
           )
  end
end
