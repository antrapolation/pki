defmodule PkiCrypto.Kdf do
  @moduledoc """
  Key derivation functions.

  - `derive_key/3` — PBKDF2-HMAC-SHA256 for password-based derivation (slow, safe for passwords)
  - `hkdf/3` — HKDF-SHA256 for high-entropy input (fast, for KEM shared secrets)
  - `derive_session_key/2` — PBKDF2 with caller-supplied salt for session keys
  """

  @pbkdf2_iterations 310_000

  @doc "Derive key from password using PBKDF2. Salt MUST be random per-user."
  def derive_key(password, salt, opts \\ []) when is_binary(password) and is_binary(salt) do
    length = Keyword.get(opts, :length, 32)
    iterations = Keyword.get(opts, :iterations, @pbkdf2_iterations)
    key = pbkdf2(password, salt, iterations, length)
    {:ok, key}
  end

  @doc "Derive session key from password + stored salt. Salt must be persisted."
  def derive_session_key(password, salt) when is_binary(password) and is_binary(salt) do
    derive_key(password, salt, iterations: @pbkdf2_iterations)
  end

  @doc "Generate a random salt for use with derive_key/derive_session_key."
  def generate_salt(length \\ 32) do
    :crypto.strong_rand_bytes(length)
  end

  @doc "HKDF-SHA256 for deriving keys from high-entropy input (KEM shared secrets, not passwords)."
  def hkdf(input_key_material, salt, opts \\ []) when is_binary(input_key_material) do
    length = Keyword.get(opts, :length, 32)
    info = Keyword.get(opts, :info, "pki_crypto")

    if length > 255 * 32, do: raise(ArgumentError, "HKDF length exceeds 255 * HashLen")

    # HKDF-Extract
    prk = :crypto.mac(:hmac, :sha256, salt, input_key_material)
    # HKDF-Expand
    okm = hkdf_expand(prk, info, length)
    {:ok, okm}
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

  defp pbkdf2(password, salt, iterations, length) do
    blocks = ceil(length / 32)

    result =
      for i <- 1..blocks, into: <<>> do
        pbkdf2_f(password, salt, iterations, i)
      end

    binary_part(result, 0, length)
  end

  defp pbkdf2_f(password, salt, iterations, block_index) do
    initial = :crypto.mac(:hmac, :sha256, password, salt <> <<block_index::32>>)

    Enum.reduce(2..iterations//1, initial, fn _, prev ->
      next = :crypto.mac(:hmac, :sha256, password, prev)
      :crypto.exor(prev, next)
    end)
  end
end
