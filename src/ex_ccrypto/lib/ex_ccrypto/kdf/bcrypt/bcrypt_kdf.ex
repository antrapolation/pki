defimpl ExCcrypto.KDF, for: ExCcrypto.KDF.BcryptContext do
  alias ExCcrypto.KDF.Bcrypt.BcryptEnvp
  alias ExCcrypto.KDF.BcryptContext
  alias ExCcrypto.KDF

  def derive(%{salt: nil} = ctx, input, opts) do
    derive(BcryptContext.random_salt(ctx), input, opts)
  end

  def derive(ctx, input, _opts) do
    # Convert 16-byte raw salt to bcrypt's 29-byte salt string format
    bcrypt_salt = Bcrypt.Base.gensalt_nif(ctx.salt, ctx.rounds, 98)
    hash_string = Bcrypt.Base.hash_password(input, bcrypt_salt)

    {:ok,
     %BcryptEnvp{}
     |> BcryptEnvp.set_derived_value(hash_string)
     |> BcryptEnvp.set_derivation_context(ctx)}
  end

  def derive!(ctx, input, opts) do
    with {:ok, res} <- KDF.derive(ctx, input, opts) do
      res
    end
  end
end
