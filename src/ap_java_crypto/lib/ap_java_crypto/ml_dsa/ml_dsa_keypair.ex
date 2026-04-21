defmodule ApJavaCrypto.MlDsa.MlDsaKeypair do
  alias ApJavaCrypto.MlDsa.MlDsaPrivateKey
  alias ApJavaCrypto.MlDsa.MlDsaPublicKey
  alias ApJavaCrypto.MlDsa.MlDsaKeypair
  alias ExCcrypto.Asymkey
  use TypedStruct

  typedstruct do
    field(:variant, atom(), default: :ml_dsa_44)
    field(:public_key, MlDsaPublicKey.t())
    field(:private_key, MlDsaPrivateKey.t())
  end

  def set_public_key(%MlDsaKeypair{} = st, pubkey) do
    %MlDsaKeypair{st | public_key: pubkey}
  end

  def set_private_key(%MlDsaKeypair{} = st, privkey) do
    %MlDsaKeypair{st | private_key: privkey}
  end
end

alias ExCcrypto.Asymkey
alias ApJavaCrypto.MlDsa.MlDsaKeypair

defimpl Asymkey, for: MlDsaKeypair do
  alias ApJavaCrypto.MlDsa.MlDsaPublicKey
  alias ApJavaCrypto.MlDsa.MlDsaPrivateKey

  def generate(%MlDsaKeypair{variant: var}) do
    with {:ok, {var, :private_key, priv}, {_, :public_key, pub}} <-
           ApJavaCrypto.generate_keypair(var) do
      {:ok,
       %MlDsaKeypair{variant: var}
       |> MlDsaKeypair.set_private_key(MlDsaPrivateKey.new(var, priv))
       |> MlDsaKeypair.set_public_key(MlDsaPublicKey.new(var, pub))}
    end
  end
end

defimpl ExCcrypto.ContextConfig, for: MlDsaKeypair do
  def set(ctx, :variant, value, _opts)
      when value in [:ml_dsa_44, :ml_dsa_65, :ml_dsa_87],
      do: %MlDsaKeypair{ctx | variant: value}

  def set(_ctx, key, _value, _opts), do: {:error, {:setter_key_not_supported, key}}

  def get(_ctx, :supported_variant, _def, _opts),
    do: [:ml_dsa_44, :ml_dsa_65, :ml_dsa_87]

  def get(ctx, :private_key, _def, _opts), do: ctx.private_key
  def get(ctx, :public_key, _def, _opts), do: ctx.public_key

  def get(_ctx, key, _default, _opts), do: {:error, {:getter_key_not_supported, key}}

  def info(_ctx, :getter_key),
    do: %{
      varialt: "Return the ML-DSA variant used for keypair generation",
      private_key: "Return private key in binary form generated",
      public_key: "Return public key in binary form generated"
    }

  def info(_ctx, :setter_key),
    do: %{
      curve: "Set curve for keypair generation"
    }

  def info(_ctx, info),
    do: %{error: "Info operation error on MlDsaKeypair. No info key '#{info}' found"}
end

alias ExCcrypto.Asymkey.Asymkeystore

defimpl Asymkeystore, for: MlDsaKeypair do
  alias ExCcrypto.Cipher
  alias ExCcrypto.Cipher.CipherContextBuilder

  def to_keystore(%MlDsaKeypair{} = kp, %{password: pass} = opts)
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
