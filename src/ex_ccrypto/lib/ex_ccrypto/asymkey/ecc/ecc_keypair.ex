defmodule ExCcrypto.Asymkey.Ecc.EccKeypair do
  alias ExCcrypto.Asymkey.Ecc.EccKeypair
  alias ExCcrypto.Asymkey.Ecc.EccPublicKey
  alias ExCcrypto.Asymkey.Ecc.EccPrivateKey

  use TypedStruct

  require Logger

  typedstruct do
    field(:curve, atom(), default: :p256)
    field(:can_sign, boolean(), default: false)
    field(:can_cipher, boolean(), default: false)
    field(:public_key, EccPublicKey.t())
    field(:private_key, EccPrivateKey.t())
  end

  def supported_curves() do
    Enum.sort(
      Enum.reject(:crypto.supports(:curves), fn c ->
        # Enum.reject(:crypto.ec_curves(), fn c ->
        # these curves never register in namedCurve structure of public_key_record
        String.starts_with?(to_string(c), "c2") or
          String.starts_with?(to_string(c), "ipsec") or
          String.starts_with?(to_string(c), "prime") or
          String.starts_with?(to_string(c), "wtls")
      end)
    )
  end

  def set_curve(ctx, curve) do
    mark_key_type(%EccKeypair{ctx | curve: curve})
  end

  def get_curve(ctx), do: ctx.curve

  def set_public_key(ctx, pubkey), do: %EccKeypair{ctx | public_key: pubkey}

  def get_public_key(ctx), do: ctx.public_key

  def set_private_key(ctx, privkey), do: %EccKeypair{ctx | private_key: privkey}

  def get_private_key(ctx), do: ctx.private_key

  def can_sign?(ctx), do: ctx.can_sign

  def can_cipher?(ctx), do: ctx.can_cipher

  defp mark_key_type(ctx) do
    cond do
      ctx.curve in [:x25519, :x448] ->
        %EccKeypair{ctx | can_sign: false, can_cipher: true}

      ctx.curve in [:ed25519] ->
        %EccKeypair{ctx | can_sign: true, can_cipher: false}

      true ->
        %EccKeypair{ctx | can_sign: true, can_cipher: true}
    end
  end

  def oid_to_curve_name({:namedCurve, curve_value}), do: oid_to_curve_name(curve_value)

  # def oid_to_curve_name({1, 3, 101, 113}), do: {:ok, :"id-Ed448"}
  # def oid_to_curve_name({1, 3, 101, 112}), do: {:ok, :"id-Ed25519"}
  # def oid_to_curve_name({1, 3, 101, 111}), do: {:ok, :"id-X448"}
  # def oid_to_curve_name({1, 3, 101, 110}), do: {:ok, :"id-X25519"}

  def oid_to_curve_name({1, 3, 101, 113}), do: {:ok, :ed448}
  def oid_to_curve_name({1, 3, 101, 112}), do: {:ok, :ed25519}
  def oid_to_curve_name({1, 3, 101, 111}), do: {:ok, :x448}
  def oid_to_curve_name({1, 3, 101, 110}), do: {:ok, :x25519}

  # def oid_to_curve_name({1, 3, 132, 0, 39}), do: {:ok, :secp571r1}
  def oid_to_curve_name({1, 3, 132, 0, 39}), do: {:ok, :sect571r1}
  # def oid_to_curve_name({1, 3, 132, 0, 38}), do: {:ok, :secp571k1}
  def oid_to_curve_name({1, 3, 132, 0, 38}), do: {:ok, :sect571k1}
  # def oid_to_curve_name({1, 3, 132, 0, 37}), do: {:ok, :secp409r1}
  def oid_to_curve_name({1, 3, 132, 0, 37}), do: {:ok, :sect409r1}
  # def oid_to_curve_name({1, 3, 132, 0, 36}), do: {:ok, :secp409k1}
  def oid_to_curve_name({1, 3, 132, 0, 36}), do: {:ok, :sect409k1}
  def oid_to_curve_name({1, 3, 132, 0, 35}), do: {:ok, :secp521r1}
  def oid_to_curve_name({1, 3, 132, 0, 34}), do: {:ok, :secp384r1}
  def oid_to_curve_name({1, 3, 132, 0, 33}), do: {:ok, :secp224r1}
  def oid_to_curve_name({1, 3, 132, 0, 32}), do: {:ok, :secp224k1}
  def oid_to_curve_name({1, 3, 132, 0, 31}), do: {:ok, :secp192k1}
  def oid_to_curve_name({1, 3, 132, 0, 30}), do: {:ok, :secp160r2}
  def oid_to_curve_name({1, 3, 132, 0, 29}), do: {:ok, :secp128r2}
  def oid_to_curve_name({1, 3, 132, 0, 28}), do: {:ok, :secp128r1}
  # def oid_to_curve_name({1, 3, 132, 0, 27}), do: {:ok, :secp233r1}
  def oid_to_curve_name({1, 3, 132, 0, 27}), do: {:ok, :sect233r1}
  # def oid_to_curve_name({1, 3, 132, 0, 26}), do: {:ok, :secp233k1}
  def oid_to_curve_name({1, 3, 132, 0, 26}), do: {:ok, :sect233k1}
  # def oid_to_curve_name({1, 3, 132, 0, 25}), do: {:ok, :secp193r2}
  def oid_to_curve_name({1, 3, 132, 0, 25}), do: {:ok, :sect193r2}
  # def oid_to_curve_name({1, 3, 132, 0, 24}), do: {:ok, :secp193r1}
  def oid_to_curve_name({1, 3, 132, 0, 24}), do: {:ok, :sect193r1}
  # def oid_to_curve_name({1, 3, 132, 0, 23}), do: {:ok, :secp131r2}
  def oid_to_curve_name({1, 3, 132, 0, 23}), do: {:ok, :sect131r2}
  # def oid_to_curve_name({1, 3, 132, 0, 22}), do: {:ok, :secp131r1}
  def oid_to_curve_name({1, 3, 132, 0, 22}), do: {:ok, :sect131r1}
  # def oid_to_curve_name({1, 3, 132, 0, 17}), do: {:ok, :secp283r1}
  def oid_to_curve_name({1, 3, 132, 0, 17}), do: {:ok, :sect283r1}
  # def oid_to_curve_name({1, 3, 132, 0, 16}), do: {:ok, :secp283k1}
  def oid_to_curve_name({1, 3, 132, 0, 16}), do: {:ok, :sect283k1}
  # def oid_to_curve_name({1, 3, 132, 0, 15}), do: {:ok, :secp162r2}
  def oid_to_curve_name({1, 3, 132, 0, 15}), do: {:ok, :sect163r2}
  def oid_to_curve_name({1, 3, 132, 0, 10}), do: {:ok, :secp256k1}
  def oid_to_curve_name({1, 3, 132, 0, 9}), do: {:ok, :secp160k1}
  def oid_to_curve_name({1, 3, 132, 0, 8}), do: {:ok, :secp160r1}
  def oid_to_curve_name({1, 3, 132, 0, 7}), do: {:ok, :secp112r2}
  def oid_to_curve_name({1, 3, 132, 0, 6}), do: {:ok, :secp112r1}
  def oid_to_curve_name({1, 3, 132, 0, 5}), do: {:ok, :sect113r2}
  def oid_to_curve_name({1, 3, 132, 0, 4}), do: {:ok, :sect113r1}
  def oid_to_curve_name({1, 3, 132, 0, 3}), do: {:ok, :sect239k1}
  def oid_to_curve_name({1, 3, 132, 0, 2}), do: {:ok, :sect163r1}
  def oid_to_curve_name({1, 3, 132, 0, 1}), do: {:ok, :sect163k1}

  def oid_to_curve_name({1, 2, 840, 10045, 3, 1, 7}), do: {:ok, :secp256r1}
  def oid_to_curve_name({1, 2, 840, 10045, 3, 1, 1}), do: {:ok, :secp192r1}

  def oid_to_curve_name({1, 3, 36, 3, 3, 2, 8, 1, 1, 14}), do: {:ok, :brainpoolP512t1}
  def oid_to_curve_name({1, 3, 36, 3, 3, 2, 8, 1, 1, 13}), do: {:ok, :brainpoolP512r1}
  def oid_to_curve_name({1, 3, 36, 3, 3, 2, 8, 1, 1, 12}), do: {:ok, :brainpoolP384t1}
  def oid_to_curve_name({1, 3, 36, 3, 3, 2, 8, 1, 1, 11}), do: {:ok, :brainpoolP384r1}
  def oid_to_curve_name({1, 3, 36, 3, 3, 2, 8, 1, 1, 10}), do: {:ok, :brainpoolP320t1}
  def oid_to_curve_name({1, 3, 36, 3, 3, 2, 8, 1, 1, 9}), do: {:ok, :brainpoolP320r1}
  def oid_to_curve_name({1, 3, 36, 3, 3, 2, 8, 1, 1, 8}), do: {:ok, :brainpoolP256t1}
  def oid_to_curve_name({1, 3, 36, 3, 3, 2, 8, 1, 1, 7}), do: {:ok, :brainpoolP256r1}
  def oid_to_curve_name({1, 3, 36, 3, 3, 2, 8, 1, 1, 6}), do: {:ok, :brainpoolP224t1}
  def oid_to_curve_name({1, 3, 36, 3, 3, 2, 8, 1, 1, 5}), do: {:ok, :brainpoolP224r1}
  def oid_to_curve_name({1, 3, 36, 3, 3, 2, 8, 1, 1, 4}), do: {:ok, :brainpoolP192t1}
  def oid_to_curve_name({1, 3, 36, 3, 3, 2, 8, 1, 1, 3}), do: {:ok, :brainpoolP192r1}
  def oid_to_curve_name({1, 3, 36, 3, 3, 2, 8, 1, 1, 2}), do: {:ok, :brainpoolP160t1}
  def oid_to_curve_name({1, 3, 36, 3, 3, 2, 8, 1, 1, 1}), do: {:ok, :brainpoolP160r1}

  def oid_to_curve_name(val), do: {:error, {:oid_not_recognized, val}}
end

defimpl ExCcrypto.ContextConfig, for: ExCcrypto.Asymkey.Ecc.EccKeypair do
  alias ExCcrypto.Asymkey.Ecc.EccKeypair
  def set(ctx, :curve, value, _opts), do: EccKeypair.set_curve(ctx, value)
  def set(ctx, :params, value, _opts), do: EccKeypair.set_curve(ctx, value)
  def set(ctx, :variant, value, _opts), do: EccKeypair.set_curve(ctx, value)
  def set(_ctx, key, _value, _opts), do: {:error, {:setter_key_not_supported, key}}

  def get(_ctx, :supported_curves, _def, _opts), do: EccKeypair.supported_curves()
  def get(_ctx, :supported_variant, _def, _opts), do: EccKeypair.supported_curves()
  def get(ctx, :can_sign?, _def, _opts), do: EccKeypair.can_sign?(ctx)
  def get(ctx, :can_cipher?, _def, _opts), do: EccKeypair.can_cipher?(ctx)
  def get(ctx, :private_key, _def, _opts), do: EccKeypair.get_private_key(ctx)
  def get(ctx, :public_key, _def, _opts), do: EccKeypair.get_public_key(ctx)

  def get(_ctx, key, _default, _opts), do: {:error, {:getter_key_not_supported, key}}

  def info(_ctx, :getter_key),
    do: %{
      curve: "Return the ECC curve used for keypair generation",
      private_key: "Return private key in binary form generated",
      public_key: "Return public key in binary form generated",
      supported_curves: "Return list of supported curve name for the engine",
      can_sign?: "Return boolean if this ECC curve can be used for data signing/verification",
      can_cipher?: "Return boolean if this ECC curve can be used for data encryption/decryption"
    }

  def info(_ctx, :setter_key),
    do: %{
      curve: "Set curve for keypair generation"
    }

  def info(_ctx, info),
    do: %{error: "Info operation error on EccKeypair. No info key '#{info}' found"}
end

defimpl ExCcrypto.Asymkey, for: ExCcrypto.Asymkey.Ecc.EccKeypair do
  alias ExCcrypto.Asymkey.Ecc.EccPublicKey
  alias ExCcrypto.Asymkey.Ecc.EccPrivateKey
  alias ExCcrypto.Asymkey.Ecc.EccKeypair

  def generate(%{curve: curve} = ctx) when curve in [:p256, :secp256r1] do
    privkey = X509.PrivateKey.new_ec(:secp256r1)

    {:ok,
     ctx
     |> EccKeypair.set_curve(curve)
     |> EccKeypair.set_private_key(%EccPrivateKey{format: :native, value: privkey})
     |> EccKeypair.set_public_key(%EccPublicKey{
       format: :native,
       value: X509.PublicKey.derive(privkey)
     })}
  end

  def generate(%{curve: curve} = ctx) do
    case Enum.member?(EccKeypair.supported_curves(), curve) do
      true ->
        privkey = X509.PrivateKey.new_ec(curve)

        {:ok,
         ctx
         |> EccKeypair.set_curve(curve)
         |> EccKeypair.set_private_key(%EccPrivateKey{format: :native, value: privkey})
         |> EccKeypair.set_public_key(%EccPublicKey{
           format: :native,
           value: X509.PublicKey.derive(privkey)
         })}

      false ->
        {:error, {:unsupported_curve, curve}}
    end
  end
end

alias ExCcrypto.Asymkey.Asymkeystore
alias ExCcrypto.Asymkey.Ecc.EccKeypair

defimpl Asymkeystore, for: EccKeypair do
  alias ExCcrypto.Cipher
  alias ExCcrypto.Cipher.CipherContextBuilder

  def to_keystore(%EccKeypair{} = kp, %{password: pass} = opts)
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

      # {:ok, :erlang.term_to_binary(%{cipher_context: ctx, cipher: c})}
    end
  end

  # def from_keystore(ks, opts) when is_binary(ks),
  #  do: from_keystore(:erlang.binary_to_term(ks), opts)

  # def from_keystore(%{cipher_context: ctx, cipher: c}, %{password: pass})
  #    when not is_nil(pass) and byte_size(pass) > 0 do
  #  with {:ok, plain} <-
  #         Cipher.cipher_init(ctx, %{password: pass})
  #         |> Cipher.cipher_update(c)
  #         |> Cipher.cipher_final() do
  #    {:ok, :erlang.binary_to_term(plain)}
  #  end
  # end
end
