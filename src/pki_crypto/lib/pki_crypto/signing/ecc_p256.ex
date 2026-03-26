defmodule PkiCrypto.Signing.ECCP256 do
  @moduledoc "ECC P-256 (secp256r1) signing algorithm using SHA-256."
  defstruct []
end

defimpl PkiCrypto.Algorithm, for: PkiCrypto.Signing.ECCP256 do
  @curve :secp256r1
  @hash :sha256
  # OID for secp256r1 (prime256v1): 1.2.840.10045.3.1.7
  @curve_oid {1, 2, 840, 10045, 3, 1, 7}

  def generate_keypair(_algo) do
    {pub_point, priv_bin} = :crypto.generate_key(:ecdh, @curve)

    # Encode private key as DER ECPrivateKey for storage
    ec_private_key = {:ECPrivateKey, 1, priv_bin,
                      {:namedCurve, @curve_oid}, pub_point, :asn1_NOVALUE}

    priv_der = :public_key.der_encode(:ECPrivateKey, ec_private_key)

    {:ok, %{
      public_key: pub_point,
      private_key: priv_der
    }}
  rescue
    e -> {:error, Exception.message(e)}
  end

  def sign(_algo, private_key_der, data) do
    {:ECPrivateKey, _, priv_bin, _, _, _} = :public_key.der_decode(:ECPrivateKey, private_key_der)
    sig = :crypto.sign(:ecdsa, @hash, data, [priv_bin, @curve])
    {:ok, sig}
  rescue
    e -> {:error, Exception.message(e)}
  end

  def verify(_algo, public_key, signature, data) do
    if :crypto.verify(:ecdsa, @hash, data, signature, [public_key, @curve]) do
      :ok
    else
      {:error, :invalid_signature}
    end
  rescue
    _ -> {:error, :invalid_signature}
  end

  def kem_encapsulate(_algo, _public_key), do: {:error, :not_supported}
  def kem_decapsulate(_algo, _private_key, _ciphertext), do: {:error, :not_supported}

  def identifier(_algo), do: "ECC-P256"
  def algorithm_type(_algo), do: :signing
end
