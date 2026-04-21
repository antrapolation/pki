defmodule ApJavaCrypto.KazSign.KazSignKeypair do
  alias ApJavaCrypto.KazSign.KazSignPrivateKey
  alias ApJavaCrypto.KazSign.KazSignPublicKey
  alias ApJavaCrypto.KazSign.KazSignKeypair
  alias ExCcrypto.Asymkey
  use TypedStruct

  typedstruct do
    field(:variant, atom(), default: :kaz_sign_128)
    field(:public_key, KazSignPublicKey.t())
    field(:private_key, KazSignPrivateKey.t())
  end

  def set_public_key(%KazSignKeypair{} = st, pubkey) do
    %KazSignKeypair{st | public_key: pubkey}
  end

  def set_private_key(%KazSignKeypair{} = st, privkey) do
    %KazSignKeypair{st | private_key: privkey}
  end
end

alias ExCcrypto.Asymkey
alias ApJavaCrypto.KazSign.KazSignKeypair

defimpl Asymkey, for: KazSignKeypair do
  alias ApJavaCrypto.KazSign.KazSignPrivateKey
  alias ApJavaCrypto.KazSign.KazSignPublicKey

  def generate(%KazSignKeypair{variant: var}) do
    with {:ok, {var, :private_key, priv}, {_, :public_key, pub}} <-
           ApJavaCrypto.generate_keypair(var) do
      {:ok,
       %KazSignKeypair{variant: var}
       |> KazSignKeypair.set_private_key(KazSignPrivateKey.new(var, priv))
       |> KazSignKeypair.set_public_key(KazSignPublicKey.new(var, pub))}
    end
  end
end

defimpl ExCcrypto.ContextConfig, for: KazSignKeypair do
  def set(ctx, :variant, value, _opts)
      when value in [:kaz_sign_128, :kaz_sign_192, :kaz_sign_256],
      do: %KazSignKeypair{ctx | variant: value}

  def set(_ctx, key, _value, _opts), do: {:error, {:setter_key_not_supported, key}}

  def get(_ctx, :supported_variant, _def, _opts),
    do: [:kaz_sign_128, :kaz_sign_192, :kaz_sign_256]

  def get(ctx, :private_key, _def, _opts), do: ctx.private_key
  def get(ctx, :public_key, _def, _opts), do: ctx.public_key

  def get(_ctx, key, _default, _opts), do: {:error, {:getter_key_not_supported, key}}

  def info(_ctx, :getter_key),
    do: %{
      varialt: "Return the KAZ-SIGN variant used for keypair generation",
      private_key: "Return private key in binary form generated",
      public_key: "Return public key in binary form generated"
    }

  def info(_ctx, :setter_key),
    do: %{
      curve: "Set curve for keypair generation"
    }

  def info(_ctx, info),
    do: %{error: "Info operation error on KazSignKeypair. No info key '#{info}' found"}
end

alias ExCcrypto.Asymkey.Asymkeystore

defimpl Asymkeystore, for: KazSignKeypair do
  alias ExCcrypto.Cipher
  alias ExCcrypto.Cipher.CipherContextBuilder

  def to_keystore(%KazSignKeypair{} = kp, %{password: pass} = opts)
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
