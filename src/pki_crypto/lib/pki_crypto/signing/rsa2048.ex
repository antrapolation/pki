defmodule PkiCrypto.Signing.RSA2048 do
  @moduledoc "RSA-2048 signing algorithm (PKCS#1 v1.5, SHA-256)."
  defstruct []
end

defimpl PkiCrypto.Algorithm, for: PkiCrypto.Signing.RSA2048 do
  def generate_keypair(_algo) do
    {:RSAPrivateKey, _ver, modulus, pub_exp, _priv_exp, _p, _q, _dp, _dq, _qinv, _other} =
      priv = :public_key.generate_key({:rsa, 2048, 65537})

    pub = {:RSAPublicKey, modulus, pub_exp}
    {:ok, %{
      public_key: :public_key.der_encode(:RSAPublicKey, pub),
      private_key: :public_key.der_encode(:RSAPrivateKey, priv)
    }}
  rescue
    _ -> {:error, :key_generation_failed}
  end

  def sign(_algo, private_key_der, data) do
    priv = :public_key.der_decode(:RSAPrivateKey, private_key_der)
    sig = :public_key.sign(data, :sha256, priv)
    {:ok, sig}
  rescue
    _ -> {:error, :signing_failed}
  end

  # public_key may be raw DER-encoded RSAPublicKey bytes
  def verify(_algo, public_key_der, signature, data) do
    pub = :public_key.der_decode(:RSAPublicKey, public_key_der)

    if :public_key.verify(data, :sha256, signature, pub) do
      :ok
    else
      {:error, :invalid_signature}
    end
  rescue
    _ -> {:error, :invalid_signature}
  end

  def kem_encapsulate(_algo, _public_key), do: {:error, :not_supported}
  def kem_decapsulate(_algo, _private_key, _ciphertext), do: {:error, :not_supported}

  def identifier(_algo), do: "RSA-2048"
  def algorithm_type(_algo), do: :signing
end
