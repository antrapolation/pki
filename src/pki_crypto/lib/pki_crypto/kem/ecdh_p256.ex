defmodule PkiCrypto.Kem.ECDHP256 do
  @moduledoc "ECDH-P256 Key Encapsulation Mechanism."
  defstruct []
end

defimpl PkiCrypto.Algorithm, for: PkiCrypto.Kem.ECDHP256 do
  @curve :secp256r1

  def generate_keypair(_algo) do
    {pub_point, priv_raw} = :crypto.generate_key(:ecdh, @curve)
    # Store as raw binaries
    {:ok, %{public_key: pub_point, private_key: priv_raw}}
  end

  def sign(_algo, _private_key, _data), do: {:error, :not_supported}
  def verify(_algo, _public_key, _signature, _data), do: {:error, :not_supported}

  def kem_encapsulate(_algo, recipient_public_key) do
    # Generate ephemeral keypair
    {ephemeral_pub, ephemeral_priv} = :crypto.generate_key(:ecdh, @curve)

    # Compute shared secret via ECDH
    raw_shared = :crypto.compute_key(:ecdh, recipient_public_key, ephemeral_priv, @curve)

    # Derive 32-byte key via HKDF (simple: SHA-256 hash)
    shared_secret = :crypto.hash(:sha256, raw_shared)

    # Ciphertext is the ephemeral public key
    {:ok, {shared_secret, ephemeral_pub}}
  rescue
    e -> {:error, Exception.message(e)}
  end

  def kem_decapsulate(_algo, private_key, ciphertext) do
    # ciphertext is the ephemeral public key
    ephemeral_pub = ciphertext

    # Compute same shared secret
    raw_shared = :crypto.compute_key(:ecdh, ephemeral_pub, private_key, @curve)
    shared_secret = :crypto.hash(:sha256, raw_shared)

    {:ok, shared_secret}
  rescue
    e -> {:error, Exception.message(e)}
  end

  def identifier(_algo), do: "ECDH-P256"
  def algorithm_type(_algo), do: :kem
end
