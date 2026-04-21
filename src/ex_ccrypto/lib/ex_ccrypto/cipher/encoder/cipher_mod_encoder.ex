defmodule ExCcrypto.Cipher.CipherModEncoder do
  @callback encode(ctx :: any(), format :: any(), opts :: any()) ::
              {:ok, encoded :: any()} | {:error, reason :: any()}

  @callback encode!(ctx :: any(), format :: any(), opts :: any()) ::
              encoded :: any() | no_return()

  @callback decode(input :: any(), format :: any(), opts :: any()) ::
              {:ok, decoded :: any()} | {:error, reason :: any()}

  @callback decode!(input :: any(), format :: any(), opts :: any()) ::
              decoded :: any() | no_return()
end
