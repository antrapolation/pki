defmodule ExCcrypto.Cipher.CipherEngine.CipherContextEncoder do
  alias ExCcrypto.Cipher.Encoder.SimpleCipherModEncoder
  alias ExCcrypto.Cipher.CipherModEncoder
  alias ExCcrypto.Cipher.CipherEngine.BlockCipherContext
  alias ExCcrypto.Cipher.CipherEngine.AeadCipherContext
  alias ExCcrypto.Cipher.CipherEngine.CipherContextEncoder
  alias ExCcrypto.Cipher.CipherEngine.CipherEnvp
  @behaviour CipherModEncoder

  def encode(ctx, to_format), do: encode(ctx, to_format, nil)

  # def encode(ctx, :with_key_and_iv, _opts) do
  #  {:ok,
  #   CipherEnvp.envp_from_context(ctx)
  #   |> CipherEnvp.set_transient_key(ctx.transient_key)
  #   |> CipherEnvp.set_iv(ctx.iv)}
  # end

  # def encode(ctx, :with_key, _opts) do
  #  {:ok,
  #   CipherEnvp.envp_from_context(ctx)
  #   |> CipherEnvp.set_transient_key(ctx.transient_key)}
  # end

  def encode(ctx, :with_iv_and_cipher, _opts) do
    {:ok,
     CipherEnvp.envp_from_context(ctx)
     |> CipherEnvp.set_iv(ctx.iv)
     |> CipherEnvp.set_cipher(ctx.cipher)}
  end

  def encode(ctx, :with_iv_without_cipher, _opts) do
    {:ok, CipherEnvp.envp_from_context(ctx) |> CipherEnvp.set_iv(ctx.iv)}
  end

  def encode(ctx, :public_info_with_cipher, _opts) do
    {:ok, CipherEnvp.envp_from_context(ctx) |> CipherEnvp.set_cipher(ctx.cipher)}
  end

  def encode(ctx, :public_info_without_cipher, _opts) do
    {:ok, CipherEnvp.envp_from_context(ctx)}
  end

  # delegate the rest of the pattern
  defdelegate encode(ctx, format, opts), to: SimpleCipherModEncoder

  def encode!(ctx, format), do: CipherContextEncoder.encode!(ctx, format, nil)

  def encode!(ctx, format, opts) do
    with {:ok, val} <- CipherContextEncoder.encode(ctx, format, opts) do
      val
    else
      {:error, :_} -> SimpleCipherModEncoder.encode(ctx, format, opts)
    end
  end

  def decode(envp, to_format \\ :native, opts \\ nil)

  def decode(%{aead: true} = envp, :native, _opts),
    do: {:ok, AeadCipherContext.context_from_envp(envp)}

  def decode(%{aead: false} = envp, :native, _opts),
    do: {:ok, BlockCipherContext.context_from_envp(envp)}

  defdelegate decode(envp, format, opts), to: SimpleCipherModEncoder

  def decode!(envp), do: CipherContextEncoder.decode!(envp, :native, nil)

  def decode!(envp, format, opts) do
    with {:ok, val} <- CipherContextEncoder.decode(envp, format, opts) do
      val
    else
      {:error, :_} -> SimpleCipherModEncoder.decode(envp, format, opts)
    end
  end
end
