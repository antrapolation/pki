defmodule PkiCrypto.Kdf do
  @moduledoc "HKDF-SHA-256 key derivation."

  def derive_key(password, salt, opts \\ []) when is_binary(password) and is_binary(salt) do
    length = Keyword.get(opts, :length, 32)
    info = Keyword.get(opts, :info, "pki_crypto")
    prk = :crypto.mac(:hmac, :sha256, salt, password)
    okm = hkdf_expand(prk, info, length)
    {:ok, okm}
  end

  def derive_session_key(password) when is_binary(password) do
    salt = :crypto.hash(:sha256, "pki_session_key_derivation")
    derive_key(password, salt, info: "session_key")
  end

  defp hkdf_expand(prk, info, length) do
    n = ceil(length / 32)
    {okm, _} =
      Enum.reduce(1..n, {<<>>, <<>>}, fn i, {acc, prev} ->
        t = :crypto.mac(:hmac, :sha256, prk, prev <> info <> <<i::8>>)
        {acc <> t, t}
      end)
    binary_part(okm, 0, length)
  end
end
