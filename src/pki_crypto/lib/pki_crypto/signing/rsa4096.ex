defmodule PkiCrypto.Signing.RSA4096 do
  @moduledoc "RSA-4096 signing algorithm."
  defstruct []
end

defimpl PkiCrypto.Algorithm, for: PkiCrypto.Signing.RSA4096 do
  @pss_opts [{:rsa_padding, :rsa_pkcs1_pss_padding}, {:rsa_pss_saltlen, 32}]

  def generate_keypair(_algo) do
    # :public_key.generate_key/1 returns an RSAPrivateKey record.
    # Extract the public key components via pattern matching.
    {:RSAPrivateKey, _ver, modulus, pub_exp, _priv_exp, _p, _q, _dp, _dq, _qinv, _other} =
      priv = :public_key.generate_key({:rsa, 4096, 65537})

    pub = {:RSAPublicKey, modulus, pub_exp}
    {:ok, %{
      public_key: :public_key.der_encode(:RSAPublicKey, pub),
      private_key: :public_key.der_encode(:RSAPrivateKey, priv)
    }}
  rescue
    _ -> {:error, :key_generation_failed}
  end

  def sign(_algo, private_key_der, data) do
    {:RSAPrivateKey, _ver, n, e, d, _p, _q, _dp, _dq, _qinv, _other} =
      :public_key.der_decode(:RSAPrivateKey, private_key_der)

    # Use :crypto.sign/5 with [e, n, d] key format for RSA-PSS support
    sig = :crypto.sign(:rsa, :sha256, data, [e, n, d], @pss_opts)
    {:ok, sig}
  rescue
    _ -> {:error, :signing_failed}
  end

  def verify(_algo, public_key_der, signature, data) do
    {:RSAPublicKey, n, e} = :public_key.der_decode(:RSAPublicKey, public_key_der)

    # Use :crypto.verify/6 with [e, n] key format for RSA-PSS support
    if :crypto.verify(:rsa, :sha256, data, signature, [e, n], @pss_opts) do
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
