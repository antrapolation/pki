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

    # Derive 32-byte key via HKDF with context binding (RFC 9180 style)
    # Bind the ephemeral public key into the KDF to prevent key-malleability attacks
    info = "pki_kem_ecdh_p256" <> ephemeral_pub
    salt = <<0::256>>
    prk = :crypto.mac(:hmac, :sha256, salt, raw_shared)
    shared_secret = binary_part(:crypto.mac(:hmac, :sha256, prk, info <> <<1::8>>), 0, 32)

    # Ciphertext is the ephemeral public key
    {:ok, {shared_secret, ephemeral_pub}}
  rescue
    _ -> {:error, :kem_encapsulate_failed}
  end

  def kem_decapsulate(_algo, private_key, ciphertext) do
    # ciphertext is the ephemeral public key
    ephemeral_pub = ciphertext

    # Compute same shared secret
    raw_shared = :crypto.compute_key(:ecdh, ephemeral_pub, private_key, @curve)

    # Same HKDF derivation with context binding
    info = "pki_kem_ecdh_p256" <> ephemeral_pub
    salt = <<0::256>>
    prk = :crypto.mac(:hmac, :sha256, salt, raw_shared)
    shared_secret = binary_part(:crypto.mac(:hmac, :sha256, prk, info <> <<1::8>>), 0, 32)

    {:ok, shared_secret}
  rescue
    _ -> {:error, :kem_decapsulate_failed}
  end

  def identifier(_algo), do: "ECDH-P256"
  def algorithm_type(_algo), do: :kem
end
