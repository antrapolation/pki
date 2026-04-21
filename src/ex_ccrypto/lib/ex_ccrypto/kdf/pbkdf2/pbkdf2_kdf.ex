defimpl ExCcrypto.KDF, for: ExCcrypto.KDF.PBKDF2Context do
  alias ExCcrypto.KDF.PBKDF2.PBKDF2Envp
  alias ExCcrypto.KDF.PBKDF2Context
  alias ExCcrypto.KDF

  def derive(%{salt: nil} = ctx, input, opts) do
    derive(PBKDF2Context.random_salt(ctx), input, opts)
  end

  def derive(ctx, input, _opts) do
    raw = :crypto.pbkdf2_hmac(ctx.hmac_algo, input, ctx.salt, ctx.iterations, ctx.out_length)

    {:ok,
     %PBKDF2Envp{}
     |> PBKDF2Envp.set_derived_value(convert_output(raw, ctx.out_format))
     |> PBKDF2Envp.set_derivation_context(ctx)}
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
