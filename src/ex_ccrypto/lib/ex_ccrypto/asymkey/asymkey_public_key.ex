# Public API
defmodule ExCcrypto.Asymkey.AsymkeyPublicKey do
  alias ExCcrypto.Asymkey.RSA.RSAPublicKey
  alias ExCcrypto.Asymkey.Ecc.EccPublicKey
  require X509.ASN1

  def to_exccrypto_public_key({{:ECPoint, _}, _} = pubkey),
    do: {:ok, EccPublicKey.to_ecc_public_key(:native, pubkey)}

  def to_exccrypto_public_key({:RSAPublicKey, _, _} = pubkey),
    do: {:ok, RSAPublicKey.to_RSA_public_key(:native, pubkey)}

  def to_exccrypto_public_key(pubkey), do: {:error, {:unsupported_public_key, pubkey}}
end
