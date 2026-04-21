defimpl ExCcrypto.KDF, for: ExCcrypto.KDF.Argon2Context do
  alias ExCcrypto.KDF.Argon2.Argon2Envp
  alias ExCcrypto.KDF.Argon2Context
  alias ExCcrypto.KDF

  require Logger

  def derive(%{salt: nil} = ctx, input, opts) do
    derive(Argon2Context.random_salt(ctx), input, opts)
  end

  def derive(ctx, input, _opts) do
    derive_engine(Argon2Context.normalize(ctx), input)
  end

  defp derive_engine(ctx, input) do
    variant =
      case ctx.variant do
        :argon2i -> 0
        :argon2d -> 1
        :argon2id -> 2
      end

    # convert to internal options structure
    eng_opts = [
      t_cost: ctx.time_cost,
      m_cost: ctx.memory_cost,
      parallel: ctx.parallel,
      format: :raw_hash,
      hashlen: ctx.out_length,
      argon2_type: variant,
      out_length: ctx.out_length
    ]

    derived = Argon2.Base.hash_password(input, ctx.salt, eng_opts)

    {:ok,
     %Argon2Envp{}
     |> Argon2Envp.set_derived_value(convert_output(derived, ctx.out_format))
     |> Argon2Envp.set_derivation_context(ctx)}
  end

  def derive!(ctx, input, opts) do
    with {:ok, res} <- KDF.derive(ctx, input, opts) do
      res
    end
  end

  defp convert_output(res, :b64) do
    case safe_decode_hex(res) do
      {:ok, bin} -> Base.encode64(bin)
      :error -> Base.encode64(res)
    end
  end

  defp convert_output(res, :bin) do
    case safe_decode_hex(res) do
      {:ok, bin} -> bin
      :error -> res
    end
  end

  defp convert_output(res, :hex) do
    case safe_decode_hex(res) do
      {:ok, bin} -> Base.encode16(bin, case: :lower)
      :error -> Base.encode16(res, case: :lower)
    end
  end

  defp convert_output(res, _format), do: res

  defp safe_decode_hex(bin) when is_binary(bin) do
    try do
      {:ok, Base.decode16!(bin, case: :mixed)}
    rescue
      ArgumentError -> :error
    end
  end
end
