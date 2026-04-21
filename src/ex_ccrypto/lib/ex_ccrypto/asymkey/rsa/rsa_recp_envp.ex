defmodule ExCcrypto.Asymkey.RSA.RSARecpEnvp do
  alias ExCcrypto.Asymkey.RSA.RSARecpEnvp
  use TypedStruct

  typedstruct do
    field(:recp_key_id, any())
    field(:cipher, binary())
  end

  def encap(recp_key_id, cipher) do
    %RSARecpEnvp{recp_key_id: recp_key_id, cipher: cipher}
  end
end
