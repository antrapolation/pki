defmodule ApJavaCrypto.SlhDsa.SlhDsaKeypair do
  alias ApJavaCrypto.SlhDsa.SlhDsaKeypair
  alias ExCcrypto.Asymkey
  use TypedStruct

  typedstruct do
    field(:variant, atom(), default: :slh_dsa_sha2_128s)
    field(:public_key, SlhDsaPublicKey.t())
    field(:private_key, SlhDsaPrivateKey.t())
  end

  def set_public_key(%SlhDsaKeypair{} = st, pubkey) do
    %SlhDsaKeypair{st | public_key: pubkey}
  end

  def set_private_key(%SlhDsaKeypair{} = st, privkey) do
    %SlhDsaKeypair{st | private_key: privkey}
  end
end

alias ExCcrypto.Asymkey
alias ApJavaCrypto.SlhDsa.SlhDsaKeypair

defimpl Asymkey, for: SlhDsaKeypair do
  alias ApJavaCrypto.SlhDsa.SlhDsaPublicKey
  alias ApJavaCrypto.SlhDsa.SlhDsaPrivateKey

  def generate(%SlhDsaKeypair{variant: var}) do
    with {:ok, {var, :private_key, priv}, {_, :public_key, pub}} <-
           ApJavaCrypto.generate_keypair(var) do
      {:ok,
       %SlhDsaKeypair{variant: var}
       |> SlhDsaKeypair.set_private_key(SlhDsaPrivateKey.new(var, priv))
       |> SlhDsaKeypair.set_public_key(SlhDsaPublicKey.new(var, pub))}
    end
  end
end

defimpl ExCcrypto.ContextConfig, for: SlhDsaKeypair do
  def set(ctx, :variant, value, _opts)
      when value in [
             :slh_dsa_sha2_128f,
             :slh_dsa_sha2_128s,
             :slh_dsa_sha2_192f,
             :slh_dsa_sha2_192s,
             :slh_dsa_sha2_256f,
             :slh_dsa_sha2_256s,
             :slh_dsa_shake_128f,
             :slh_dsa_shake_128s,
             :slh_dsa_shake_192f,
             :slh_dsa_shake_192s,
             :slh_dsa_shake_256f,
             :slh_dsa_shake_256s
           ],
      do: %SlhDsaKeypair{ctx | variant: value}

  def set(_ctx, key, _value, _opts), do: {:error, {:setter_key_not_supported, key}}

  def get(_ctx, :supported_variant, _def, _opts),
    do: [
      :slh_dsa_sha2_128f,
      :slh_dsa_sha2_128s,
      :slh_dsa_sha2_192f,
      :slh_dsa_sha2_192s,
      :slh_dsa_sha2_256f,
      :slh_dsa_sha2_256s,
      :slh_dsa_shake_128f,
      :slh_dsa_shake_128s,
      :slh_dsa_shake_192f,
      :slh_dsa_shake_192s,
      :slh_dsa_shake_256f,
      :slh_dsa_shake_256s
    ]

  def get(ctx, :private_key, _def, _opts), do: ctx.private_key
  def get(ctx, :public_key, _def, _opts), do: ctx.public_key

  def get(_ctx, key, _default, _opts), do: {:error, {:getter_key_not_supported, key}}

  def info(_ctx, :getter_key),
    do: %{
      varialt: "Return the SLH-DSA variant used for keypair generation",
      private_key: "Return private key in binary form generated",
      public_key: "Return public key in binary form generated"
    }

  def info(_ctx, :setter_key),
    do: %{
      curve: "Set curve for keypair generation"
    }

  def info(_ctx, info),
    do: %{error: "Info operation error on SlhDsaKeypair. No info key '#{info}' found"}
end

alias ExCcrypto.Asymkey.Asymkeystore

defimpl Asymkeystore, for: SlhDsaKeypair do
  alias ExCcrypto.Cipher
  alias ExCcrypto.Cipher.CipherContextBuilder

  def to_keystore(%SlhDsaKeypair{} = kp, %{password: pass} = opts)
      when not is_nil(pass) and byte_size(pass) > 0 do
    with {:ok, %{cipher_context: ctx, cipher: c}} <-
           CipherContextBuilder.user_key_cipher_context(:aes_256_gcm, pass)
           |> Cipher.cipher_init()
           |> Cipher.cipher_update(:erlang.term_to_binary(kp))
           |> Cipher.cipher_final() do
      case Map.get(opts, :return_raw) do
        x when x in [nil, false] ->
          {:ok, :erlang.term_to_binary(%{cipher_context: ctx, cipher: c})}

        true ->
          {:ok, %{cipher_context: ctx, cipher: c}}
      end
    end
  end
end
