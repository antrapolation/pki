defmodule ApJavaCrypto.KazKem.KazKemCipher do
  alias ApJavaCrypto.KazKem.KazKemCipher
  use TypedStruct

  typedstruct do
    field(:cipher, binary())
    field(:cipher_context, any())
    field(:kdf_context, any())
    field(:recp_envp, list(), default: [])
    field(:session_info, map(), default: %{})
  end

  require Logger

  def set_cipher(ctx, cipher) do
    %KazKemCipher{ctx | cipher: cipher}
  end

  def clear_cipher(%KazKemCipher{} = cipher) do
    %KazKemCipher{cipher | cipher: nil}
  end

  def get_cipher(ctx), do: ctx[:cipher]

  def set_cipher_context(ctx, cipher_context),
    do: %KazKemCipher{ctx | cipher_context: cipher_context}

  def set_kdf_context(ctx, kdf_context),
    do: %KazKemCipher{ctx | kdf_context: kdf_context}

  def set_recp_envp(ctx, envp) when is_list(envp) do
    %KazKemCipher{ctx | recp_envp: envp}
  end

  def add_recp_envp(ctx, envp) when not is_list(envp) do
    %KazKemCipher{ctx | recp_envp: ctx.recp_envp ++ [envp]}
  end

  def get_recp_envp(ctx) do
    case ctx[:recp_envp] do
      nil -> []
      res -> res
    end
  end

  def set_session_info(ctx, key, value) do
    case Map.has_key?(ctx.session_info, key) do
      true ->
        %KazKemCipher{ctx | session_info: %{ctx.session_info | key => value}}

      false ->
        %KazKemCipher{ctx | session_info: Map.put_new(ctx.session_info, key, value)}
    end
  end

  def get_session_info(ctx, key, default \\ nil) do
    case ctx.session_info[key] do
      nil -> default
      res -> res
    end
  end

  def is_recipient?(ctx, kid) do
    case get_recipient_envp(ctx, kid) do
      nil -> false
      _ -> true
    end
  end

  def get_recipient_envp(ctx, kid) do
    Enum.find(ctx.recp_envp, fn val -> val.recp_key_id == kid end)
  end
end

alias ApJavaCrypto.KazKem.KazKemCipher

defimpl ExCcrypto.Asymkey.AsymkeyDecrypt, for: KazKemCipher do
  alias ApJavaCrypto.KazKem.KazKemEnvp
  alias ApJavaCrypto.KazKem.KazKemPublicKey
  alias ApJavaCrypto.KazKem.KazKemPrivateKey
  alias ExCcrypto.ContextConfig
  alias ExCcrypto.Asymkey.AsymkeyDecrypt
  alias ExCcrypto.KDF
  alias ExCcrypto.UniqueKeyIdGenerator
  alias ExCcrypto.Cipher

  require Logger

  def decrypt_init(ctx, public_key, private_key, opts \\ nil)

  def decrypt_init(ctx, %KazKemPublicKey{} = public_key, %KazKemPrivateKey{} = private_key, _opts) do
    kid = UniqueKeyIdGenerator.unique_key_id(public_key)

    case KazKemCipher.is_recipient?(ctx, kid) do
      true ->
        %KazKemEnvp{} = envp = KazKemCipher.get_recipient_envp(ctx, kid)
        recp_cc = envp.cipher_context

        {:ok, shared_secret} =
          ApJavaCrypto.decapsulate(
            envp.recp_cipher,
            {private_key.variant, :private_key, private_key.value}
          )

        kdf_output =
          ContextConfig.set(
            envp.kdf_context,
            :out_length,
            ContextConfig.get(recp_cc, :key_byte_size)
          )
          |> KDF.derive!(shared_secret)

        with {:ok, key} <-
               Cipher.cipher_init(recp_cc, %{
                 session_key: ContextConfig.get(kdf_output, :derived_value)
               })
               |> Cipher.cipher_update(envp.cipher)
               |> Cipher.cipher_final() do
          {:ok,
           KazKemCipher.set_session_info(
             ctx,
             :session_cipher,
             Cipher.cipher_init(ctx.cipher_context, %{session_key: key})
           )}
        else
          {:error, :decryption_failed} -> {:error, :recipient_decryption_failed}
        end

      false ->
        {:error, :not_a_recipient}
    end
  end

  def decrypt_update(ctx, data) do
    KazKemCipher.set_session_info(
      ctx,
      :session_cipher,
      Cipher.cipher_update(KazKemCipher.get_session_info(ctx, :session_cipher), data)
    )
  end

  def decrypt_final(ctx, _opts) do
    with {:ok, plain} <- Cipher.cipher_final(KazKemCipher.get_session_info(ctx, :session_cipher)) do
      plain
    end
  end

  def decrypt(ctx, public_key, private_key, data, opts \\ nil) do
    with {:ok, ctx} <- AsymkeyDecrypt.decrypt_init(ctx, public_key, private_key, opts) do
      AsymkeyDecrypt.decrypt_update(ctx, data)
      |> AsymkeyDecrypt.decrypt_final(opts)
    end
  end
end
