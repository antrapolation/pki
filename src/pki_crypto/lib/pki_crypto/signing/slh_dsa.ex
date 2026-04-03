defmodule PkiCrypto.Signing.SlhDsaSha2128f do
  @moduledoc "SLH-DSA-SHA2-128f (FIPS 205) — NIST PQC Level 1 fast signature via liboqs NIF."
  defstruct []
end

defmodule PkiCrypto.Signing.SlhDsaSha2128s do
  @moduledoc "SLH-DSA-SHA2-128s (FIPS 205) — NIST PQC Level 1 small signature via liboqs NIF."
  defstruct []
end

defmodule PkiCrypto.Signing.SlhDsaSha2192f do
  @moduledoc "SLH-DSA-SHA2-192f (FIPS 205) — NIST PQC Level 3 fast signature via liboqs NIF."
  defstruct []
end

defmodule PkiCrypto.Signing.SlhDsaSha2192s do
  @moduledoc "SLH-DSA-SHA2-192s (FIPS 205) — NIST PQC Level 3 small signature via liboqs NIF."
  defstruct []
end

defmodule PkiCrypto.Signing.SlhDsaSha2256f do
  @moduledoc "SLH-DSA-SHA2-256f (FIPS 205) — NIST PQC Level 5 fast signature via liboqs NIF."
  defstruct []
end

defmodule PkiCrypto.Signing.SlhDsaSha2256s do
  @moduledoc "SLH-DSA-SHA2-256s (FIPS 205) — NIST PQC Level 5 small signature via liboqs NIF."
  defstruct []
end

for {module, algo} <- [
  {PkiCrypto.Signing.SlhDsaSha2128f, "SLH-DSA-SHA2-128f"},
  {PkiCrypto.Signing.SlhDsaSha2128s, "SLH-DSA-SHA2-128s"},
  {PkiCrypto.Signing.SlhDsaSha2192f, "SLH-DSA-SHA2-192f"},
  {PkiCrypto.Signing.SlhDsaSha2192s, "SLH-DSA-SHA2-192s"},
  {PkiCrypto.Signing.SlhDsaSha2256f, "SLH-DSA-SHA2-256f"},
  {PkiCrypto.Signing.SlhDsaSha2256s, "SLH-DSA-SHA2-256s"}
] do
  defimpl PkiCrypto.Algorithm, for: module do
    @algo algo
    def generate_keypair(_), do: PkiOqsNif.keygen(@algo)
    def sign(_, private_key, data), do: PkiOqsNif.sign(@algo, private_key, data)
    def verify(_, public_key, signature, data), do: PkiOqsNif.verify(@algo, public_key, signature, data)
    def kem_encapsulate(_, _), do: {:error, :not_supported}
    def kem_decapsulate(_, _, _), do: {:error, :not_supported}
    def identifier(_), do: @algo
    def algorithm_type(_), do: :signing
  end
end
