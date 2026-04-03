defmodule PkiCrypto.Signing.MlDsa44 do
  @moduledoc "ML-DSA-44 (FIPS 204) — NIST PQC Level 2 digital signature via liboqs NIF."
  defstruct []
end

defmodule PkiCrypto.Signing.MlDsa65 do
  @moduledoc "ML-DSA-65 (FIPS 204) — NIST PQC Level 3 digital signature via liboqs NIF."
  defstruct []
end

defmodule PkiCrypto.Signing.MlDsa87 do
  @moduledoc "ML-DSA-87 (FIPS 204) — NIST PQC Level 5 digital signature via liboqs NIF."
  defstruct []
end

defimpl PkiCrypto.Algorithm, for: PkiCrypto.Signing.MlDsa44 do
  def generate_keypair(_), do: PkiOqsNif.keygen("ML-DSA-44")
  def sign(_, private_key, data), do: PkiOqsNif.sign("ML-DSA-44", private_key, data)
  def verify(_, public_key, signature, data), do: PkiOqsNif.verify("ML-DSA-44", public_key, signature, data)
  def kem_encapsulate(_, _), do: {:error, :not_supported}
  def kem_decapsulate(_, _, _), do: {:error, :not_supported}
  def identifier(_), do: "ML-DSA-44"
  def algorithm_type(_), do: :signing
end

defimpl PkiCrypto.Algorithm, for: PkiCrypto.Signing.MlDsa65 do
  def generate_keypair(_), do: PkiOqsNif.keygen("ML-DSA-65")
  def sign(_, private_key, data), do: PkiOqsNif.sign("ML-DSA-65", private_key, data)
  def verify(_, public_key, signature, data), do: PkiOqsNif.verify("ML-DSA-65", public_key, signature, data)
  def kem_encapsulate(_, _), do: {:error, :not_supported}
  def kem_decapsulate(_, _, _), do: {:error, :not_supported}
  def identifier(_), do: "ML-DSA-65"
  def algorithm_type(_), do: :signing
end

defimpl PkiCrypto.Algorithm, for: PkiCrypto.Signing.MlDsa87 do
  def generate_keypair(_), do: PkiOqsNif.keygen("ML-DSA-87")
  def sign(_, private_key, data), do: PkiOqsNif.sign("ML-DSA-87", private_key, data)
  def verify(_, public_key, signature, data), do: PkiOqsNif.verify("ML-DSA-87", public_key, signature, data)
  def kem_encapsulate(_, _), do: {:error, :not_supported}
  def kem_decapsulate(_, _, _), do: {:error, :not_supported}
  def identifier(_), do: "ML-DSA-87"
  def algorithm_type(_), do: :signing
end
