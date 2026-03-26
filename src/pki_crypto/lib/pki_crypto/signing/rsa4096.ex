defmodule PkiCrypto.Signing.RSA4096 do
  @moduledoc "RSA-4096 signing algorithm."
  defstruct []
end

defimpl PkiCrypto.Algorithm, for: PkiCrypto.Signing.RSA4096 do
  def generate_keypair(_algo) do
    # :public_key.generate_key/1 returns an RSAPrivateKey record.
    # Extract the public key components (modulus and publicExponent) from it.
    priv = :public_key.generate_key({:rsa, 4096, 65537})
    modulus = elem(priv, 2)
    pub_exp = elem(priv, 3)
    pub = {:RSAPublicKey, modulus, pub_exp}
    {:ok, %{
      public_key: :public_key.der_encode(:RSAPublicKey, pub),
      private_key: :public_key.der_encode(:RSAPrivateKey, priv)
    }}
  rescue
    e -> {:error, Exception.message(e)}
  end

  def sign(_algo, private_key_der, data) do
    priv = :public_key.der_decode(:RSAPrivateKey, private_key_der)
    sig = :public_key.sign(data, :sha256, priv)
    {:ok, sig}
  rescue
    e -> {:error, Exception.message(e)}
  end

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

  def identifier(_algo), do: "RSA-4096"
  def algorithm_type(_algo), do: :signing
end
