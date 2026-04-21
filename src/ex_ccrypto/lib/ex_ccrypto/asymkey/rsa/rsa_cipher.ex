defmodule ExCcrypto.Asymkey.RSA.RSACipher do
  alias ExCcrypto.Asymkey.RSA.RSACipher
  use TypedStruct

  typedstruct do
    field(:cipher, binary())
    field(:cipher_context, any())
    # field(:kdf_context, any())
    field(:recp_envp, list(), default: [])
    field(:session_info, map(), default: %{})
  end

  require Logger

  def set_cipher(ctx, cipher) do
    %RSACipher{ctx | cipher: cipher}
  end

  def clear_cipher(%RSACipher{} = cipher) do
    %RSACipher{cipher | cipher: nil}
  end

  def get_cipher(ctx), do: ctx[:cipher]

  def set_cipher_context(ctx, cipher_context),
    do: %RSACipher{ctx | cipher_context: cipher_context}

  # def set_kdf_context(ctx, kdf_context),
  #  do: %RSACipher{ctx | kdf_context: kdf_context}

  def set_recp_envp(ctx, envp) when is_list(envp) do
    %RSACipher{ctx | recp_envp: envp}
  end

  def add_recp_envp(ctx, envp) when not is_list(envp) do
    %RSACipher{ctx | recp_envp: ctx.recp_envp ++ [envp]}
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
        %RSACipher{ctx | session_info: %{ctx.session_info | key => value}}

      false ->
        %RSACipher{ctx | session_info: Map.put_new(ctx.session_info, key, value)}
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

defimpl ExCcrypto.Asymkey.AsymkeyDecrypt, for: ExCcrypto.Asymkey.RSA.RSACipher do
  alias ExCcrypto.Asymkey.RSA.RSACipher
  alias ExCcrypto.Asymkey.RSA.RSAPrivateKey
  alias ExCcrypto.Asymkey.AsymkeyDecrypt
  alias ExCcrypto.Asymkey.KeyEncoding
  alias ExCcrypto.UniqueKeyIdGenerator
  alias ExCcrypto.Cipher

  require Logger

  def decrypt_init(ctx, public_key, private_key, opts \\ nil)

  def decrypt_init(ctx, pubkey, %RSAPrivateKey{} = privkey, opts) do
    decrypt_init(ctx, pubkey, KeyEncoding.to_native!(privkey), opts)
  end

  def decrypt_init(ctx, public_key, private_key, _opts) do
    kid = UniqueKeyIdGenerator.unique_key_id(public_key)

    case RSACipher.is_recipient?(ctx, kid) do
      true ->
        envp = RSACipher.get_recipient_envp(ctx, kid)

        try do
          key = :public_key.decrypt_private(envp.cipher, private_key)

          {:ok,
           RSACipher.set_session_info(
             ctx,
             :session_cipher,
             Cipher.cipher_init(ctx.cipher_context, %{session_key: key})
           )}
        rescue
          _error -> {:error, :recipient_decryption_failed}
        end

      false ->
        {:error, :not_a_recipient}
    end
  end

  def decrypt_update(ctx, data) do
    RSACipher.set_session_info(
      ctx,
      :session_cipher,
      Cipher.cipher_update(RSACipher.get_session_info(ctx, :session_cipher), data)
    )
  end

  def decrypt_final(ctx, _opts) do
    with {:ok, plain} <- Cipher.cipher_final(RSACipher.get_session_info(ctx, :session_cipher)) do
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
