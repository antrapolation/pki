# Public Struct
defmodule ExCcrypto.Asymkey.Ecc.EciesEnvp do
  alias ExCcrypto.Asymkey.Ecc.EciesEnvp
  use TypedStruct

  typedstruct do
    field(:cipher, binary())
    field(:recp_key_id, any())
    field(:cipher_context, any())
    field(:kdf_context, any())
    field(:sender_public, any())
  end

  def set_cipher(ctx, cipher) do
    %EciesEnvp{ctx | cipher: cipher}
  end

  def set_cipher_context(ctx, cipher_context) do
    %EciesEnvp{ctx | cipher_context: cipher_context}
  end

  def set_kdf_context(ctx, kdf_context) do
    %EciesEnvp{ctx | kdf_context: kdf_context}
  end

  def set_recp_key_id(ctx, key_id) do
    %EciesEnvp{ctx | recp_key_id: key_id}
  end

  def set_sender_public(ctx, pubkey) do
    %EciesEnvp{ctx | sender_public: pubkey}
  end
end
