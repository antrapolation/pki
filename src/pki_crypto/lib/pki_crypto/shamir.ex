defmodule PkiCrypto.Shamir do
  @moduledoc "Shamir's Secret Sharing — split and recover secrets."

  def split(secret, k, n) when k >= 2 and k <= n and is_binary(secret) do
    shares = KeyX.Shamir.split_secret(k, n, secret)
    {:ok, shares}
  rescue
    e -> {:error, Exception.message(e)}
  end

  def split(_secret, _k, _n), do: {:error, :invalid_threshold}

  def recover(shares) when is_list(shares) and length(shares) >= 1 do
    secret = KeyX.Shamir.recover_secret(shares)
    {:ok, secret}
  rescue
    e -> {:error, Exception.message(e)}
  end
end
