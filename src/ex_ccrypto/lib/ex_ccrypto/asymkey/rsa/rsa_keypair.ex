# Public Struct
defmodule ExCcrypto.Asymkey.RSA.RSAKeypair do
  alias ExCcrypto.Asymkey.RSA.RSAPublicKey
  alias ExCcrypto.Asymkey.RSA.RSAPrivateKey
  alias ExCcrypto.Asymkey.RSA.RSAKeypair
  use TypedStruct

  @type valid_keysize :: 1024 | 2048 | 4096 | 8192

  typedstruct do
    field(:keysize, valid_keysize(), default: 2048)
    field(:public_exponent, any(), default: 65537)
    field(:public_key, any())
    field(:private_key, any())
  end

  @spec new(valid_keysize) :: RSAKeypair.t()
  def new(keysize \\ 2048)

  def new(keysize) when not is_integer(keysize), do: new(String.to_integer(to_string(keysize)))

  def new(keysize) do
    %RSAKeypair{keysize: keysize}
  end

  def supported_keysizes(), do: [1024, 2048, 4096, 8192]

  def set_private_public_key(
        %RSAKeypair{} = rsa,
        {:RSAPrivateKey, :"two-prime", mod, exp, _, _, _, _, _, _, _} = privkey
      ) do
    %RSAKeypair{
      rsa
      | private_key: RSAPrivateKey.encap(privkey),
        public_key: RSAPublicKey.encap({:RSAPublicKey, mod, exp})
    }
  end
end

alias ExCcrypto.Asymkey
alias ExCcrypto.Asymkey.RSA.RSAKeypair

defimpl Asymkey, for: RSAKeypair do
  alias ExCcrypto.Asymkey.RSA.RSAKeypair

  def generate(%RSAKeypair{} = kp) do
    case Enum.member?(RSAKeypair.supported_keysizes(), kp.keysize) do
      true ->
        rkp = :public_key.generate_key({:rsa, kp.keysize, kp.public_exponent})

        {:ok, RSAKeypair.set_private_public_key(kp, rkp)}

      false ->
        {:error, {:invalid_keysize, kp.keysize, RSAKeypair.supported_keysizes()}}
    end
  end
end

alias ExCcrypto.ContextConfig

defimpl ContextConfig, for: RSAKeypair do
  def set(ctx, :keysize, value, _opts), do: %RSAKeypair{ctx | keysize: value}
  def set(ctx, :params, value, _opts), do: %RSAKeypair{ctx | keysize: value}
  def set(_ctx, key, _value, _opts), do: {:error, {:setter_key_not_supported, key}}

  def get(_ctx, :supported_keysizes, _def, _opts), do: RSAKeypair.supported_keysizes()
  def get(ctx, :private_key, _def, _opts), do: ctx.private_key
  def get(ctx, :public_key, _def, _opts), do: ctx.public_key

  def get(_ctx, key, _default, _opts), do: {:error, {:getter_key_not_supported, key}}

  def info(_ctx, :getter_key),
    do: %{
      keysize: "Return the RSA keysize used for keypair generation",
      private_key: "Return private key in binary form generated",
      public_key: "Return public key in binary form generated",
      supported_keysizes: "Return list of supported keysizes for the engine"
    }

  def info(_ctx, :setter_key),
    do: %{
      keysize: "Set keysize for keypair generation"
    }

  def info(_ctx, info),
    do: %{error: "Info operation error on RSAKeypair. No info key '#{info}' found"}
end

alias ExCcrypto.Asymkey.Asymkeystore

defimpl Asymkeystore, for: ExCcrypto.Asymkey.RSA.RSAKeypair do
  alias ExCcrypto.Cipher
  alias ExCcrypto.Cipher.CipherContextBuilder

  def to_keystore(%RSAKeypair{} = kp, %{password: pass})
      when not is_nil(pass) and byte_size(pass) > 0 do
    with {:ok, %{cipher_context: ctx, cipher: c}} <-
           CipherContextBuilder.user_key_cipher_context(:aes_256_gcm, pass)
           |> Cipher.cipher_init()
           |> Cipher.cipher_update(:erlang.term_to_binary(kp))
           |> Cipher.cipher_final() do
      {:ok, :erlang.term_to_binary(%{cipher_context: ctx, cipher: c})}
    end
  end
end
