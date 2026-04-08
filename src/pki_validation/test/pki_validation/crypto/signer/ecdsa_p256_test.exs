defmodule PkiValidation.Crypto.Signer.EcdsaP256Test do
  use ExUnit.Case, async: true

  alias PkiValidation.Crypto.Signer.EcdsaP256

  setup do
    {pub_point, priv_scalar} = :crypto.generate_key(:ecdh, :secp256r1)
    {:ok, pub_point: pub_point, priv_scalar: priv_scalar}
  end

  test "decode_private_key/1 passes raw ECC scalar bytes through unchanged", %{priv_scalar: priv} do
    assert EcdsaP256.decode_private_key(priv) == priv
  end

  test "algorithm_identifier_der/0 returns the RFC 5754 ecdsa-with-SHA256 DER", _ctx do
    der = EcdsaP256.algorithm_identifier_der()
    assert is_binary(der)
    # ecdsa-with-SHA256 OID is 1.2.840.10045.4.3.2, encoded as
    # 0x06 0x08 0x2A 0x86 0x48 0xCE 0x3D 0x04 0x03 0x02 inside a SEQUENCE.
    # The full AlgorithmIdentifier (no params) is:
    #   SEQUENCE { OID 1.2.840.10045.4.3.2 }
    # = 30 0A 06 08 2A 86 48 CE 3D 04 03 02
    assert der == <<0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02>>
  end

  test "algorithm_identifier_record/0 returns the matching Erlang record" do
    # The OID inside the record must match the OID embedded in the DER blob
    # above (1.2.840.10045.4.3.2). ECDSA has no params (asn1_NOVALUE).
    assert EcdsaP256.algorithm_identifier_record() ==
             {:AlgorithmIdentifier, {1, 2, 840, 10045, 4, 3, 2}, :asn1_NOVALUE}
  end

  test "sign/2 produces a signature verifiable with :public_key.verify/4", %{
    pub_point: pub,
    priv_scalar: priv
  } do
    tbs = "test message to sign" |> :erlang.term_to_binary()

    decoded_priv = EcdsaP256.decode_private_key(priv)
    signature = EcdsaP256.sign(tbs, decoded_priv)

    assert is_binary(signature)

    p256_oid = {1, 2, 840, 10045, 3, 1, 7}

    assert :public_key.verify(
             tbs,
             :sha256,
             signature,
             {{:ECPoint, pub}, {:namedCurve, p256_oid}}
           )
  end
end
