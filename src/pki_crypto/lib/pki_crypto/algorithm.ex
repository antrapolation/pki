defprotocol PkiCrypto.Algorithm do
  @moduledoc """
  Protocol for cryptographic algorithm dispatch.

  Each algorithm (RSA, ECC, KEM variants) implements this protocol
  via a struct. Dispatch is automatic based on the struct type.
  """

  @doc """
  Generate a keypair. Returns {:ok, %{public_key: binary, private_key: binary}} or {:error, reason}.
  Key format is algorithm-specific (DER for RSA, raw EC point binary for ECC/KEM).
  """
  def generate_keypair(algorithm)

  @doc "Sign data. Returns {:ok, signature_binary} or {:error, reason}"
  def sign(algorithm, private_key, data)

  @doc "Verify signature. Returns :ok or {:error, :invalid_signature}"
  def verify(algorithm, public_key, signature, data)

  @doc "KEM encapsulate. Returns {:ok, {shared_secret, ciphertext}} or {:error, :not_supported}"
  def kem_encapsulate(algorithm, public_key)

  @doc "KEM decapsulate. Returns {:ok, shared_secret} or {:error, reason}"
  def kem_decapsulate(algorithm, private_key, ciphertext)

  @doc "Algorithm identifier string for DB storage and wire format"
  def identifier(algorithm)

  @doc "Algorithm type — :signing, :kem, or :dual"
  def algorithm_type(algorithm)
end
