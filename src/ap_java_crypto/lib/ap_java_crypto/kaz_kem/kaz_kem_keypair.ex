defmodule ApJavaCrypto.KazKem.KazKemKeypair do
  alias ApJavaCrypto.KazKem.KazKemKeypair
  alias ExCcrypto.Asymkey
  use TypedStruct

  typedstruct do
    field(:variant, atom(), default: :kaz_kem_128)
    field(:public_key, KazKemPublicKey.t())
    field(:private_key, KazKemPrivateKey.t())
  end

  def set_public_key(%KazKemKeypair{} = st, pubkey) do
    %KazKemKeypair{st | public_key: pubkey}
  end

  def set_private_key(%KazKemKeypair{} = st, privkey) do
    %KazKemKeypair{st | private_key: privkey}
  end
end

alias ExCcrypto.Asymkey
alias ApJavaCrypto.KazKem.KazKemKeypair

defimpl Asymkey, for: KazKemKeypair do
  alias ApJavaCrypto.KazKem.KazKemPublicKey
  alias ApJavaCrypto.KazKem.KazKemPrivateKey

  def generate(%KazKemKeypair{variant: var}) do
    with {:ok, {var, :private_key, priv}, {_, :public_key, pub}} <-
           ApJavaCrypto.generate_keypair(var) do
      {:ok,
       %KazKemKeypair{variant: var}
       |> KazKemKeypair.set_private_key(KazKemPrivateKey.new(var, priv))
       |> KazKemKeypair.set_public_key(KazKemPublicKey.new(var, pub))}
    end
  end
end

defimpl ExCcrypto.ContextConfig, for: KazKemKeypair do
  def set(ctx, :variant, value, _opts)
      when value in [:kaz_kem_128, :kaz_kem_192, :kaz_kem_256],
      do: %KazKemKeypair{ctx | variant: value}

  def set(_ctx, key, _value, _opts), do: {:error, {:setter_key_not_supported, key}}

  def get(_ctx, :supported_variant, _def, _opts),
    do: [:kaz_kem_128, :kaz_kem_192, :kaz_kem_256]

  def get(ctx, :private_key, _def, _opts), do: ctx.private_key
  def get(ctx, :public_key, _def, _opts), do: ctx.public_key

  def get(_ctx, key, _default, _opts), do: {:error, {:getter_key_not_supported, key}}

  def info(_ctx, :getter_key),
    do: %{
      varialt: "Return the KAZ-KEM variant used for keypair generation",
      private_key: "Return private key in binary form generated",
      public_key: "Return public key in binary form generated"
    }

  def info(_ctx, :setter_key),
    do: %{
      curve: "Set curve for keypair generation"
    }

  def info(_ctx, info),
    do: %{error: "Info operation error on KazKemKeypair. No info key '#{info}' found"}
end

alias ExCcrypto.Asymkey.Asymkeystore

defimpl Asymkeystore, for: KazKemKeypair do
  alias ExCcrypto.Cipher
  alias ExCcrypto.Cipher.CipherContextBuilder

  def to_keystore(%KazKemKeypair{} = kp, %{password: pass} = opts)
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
