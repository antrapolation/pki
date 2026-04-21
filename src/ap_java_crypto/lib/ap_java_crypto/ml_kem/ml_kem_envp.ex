defmodule ApJavaCrypto.MlKem.MlKemEnvp do
  alias ApJavaCrypto.MlKem.MlKemEnvp

  # to encapsulate session key for each recipient
  use TypedStruct

  typedstruct do
    field(:cipher, binary())
    field(:recp_key_id, any())
    field(:cipher_context, any())
    field(:kdf_context, any())
    field(:recp_cipher, any())
  end

  def set_cipher(ctx, cipher) do
    %MlKemEnvp{ctx | cipher: cipher}
  end

  def set_cipher_context(ctx, cipher_context) do
    %MlKemEnvp{ctx | cipher_context: cipher_context}
  end

  def set_kdf_context(ctx, kdf_context) do
    %MlKemEnvp{ctx | kdf_context: kdf_context}
  end

  def set_recp_key_id(ctx, key_id) do
    %MlKemEnvp{ctx | recp_key_id: key_id}
  end

  def set_recipient_cipher(ctx, recp_cipher) do
    %MlKemEnvp{ctx | recp_cipher: recp_cipher}
  end
end
