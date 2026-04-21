defimpl ExCcrypto.KDF, for: ExCcrypto.KDF.ScryptContext do
  alias ExCcrypto.KDF.Scrypt.ScryptEnvp
  alias ExCcrypto.KDF.ScryptContext
  alias ExCcrypto.KDF

  def derive(%{salt: nil} = ctx, input, opts) do
    derive(ScryptContext.random_salt(ctx), input, opts)
  end

  def derive(ctx, input, _opts) do
    raw = :scrypt.scrypt(input, ctx.salt, ctx.n, ctx.r, ctx.p, ctx.out_length)

    {:ok,
     %ScryptEnvp{}
     |> ScryptEnvp.set_derived_value(convert_output(raw, ctx.out_format))
     |> ScryptEnvp.set_derivation_context(ctx)}
  end

  def derive!(ctx, input, opts) do
    with {:ok, res} <- KDF.derive(ctx, input, opts) do
      res
    end
  end

  defp convert_output(bin, :hex), do: Base.encode16(bin, case: :lower)
  defp convert_output(bin, :b64), do: Base.encode64(bin)
  defp convert_output(bin, _), do: bin
end
