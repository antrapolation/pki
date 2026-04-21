# Public API
defmodule ExCcrypto.KDF.KDFContextBuilder do
  alias ExCcrypto.KDF.Argon2Context
  alias ExCcrypto.KDF.PBKDF2Context
  alias ExCcrypto.KDF.ScryptContext
  alias ExCcrypto.KDF.BcryptContext

  def default_kdf_context(), do: kdf_context(:argon2)

  def kdf_context(:argon2), do: %Argon2Context{}
  def kdf_context(:pbkdf2), do: %PBKDF2Context{}
  def kdf_context(:scrypt), do: %ScryptContext{}
  def kdf_context(:bcrypt), do: %BcryptContext{}

  def kdf_context(%Argon2Context{} = ctx), do: ctx
  def kdf_context(%PBKDF2Context{} = ctx), do: ctx
  def kdf_context(%ScryptContext{} = ctx), do: ctx
  def kdf_context(%BcryptContext{} = ctx), do: ctx

  def kdf_context(algo), do: {:error, {:not_supported_kdf_algo, algo}}
end
