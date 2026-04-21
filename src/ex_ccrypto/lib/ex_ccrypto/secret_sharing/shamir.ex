defmodule ExCcrypto.SecretSharing.Shamir do
  alias ExCcrypto.SecretSharing.Shamir
  alias ExCcrypto.Utils.ConditionUtils

  defstruct [
    {:total_shares, 3},
    {:required_shares, 2},
    {:shares, []}
  ]

  def set_split_policy(req, total) do
    %{%Shamir{} | total_shares: total, required_shares: req}
  end

  def split(secret, params \\ %ExCcrypto.SecretSharing.Shamir{})

  def split(secret, %{total_shares: ttl, required_shares: req} = params) do
    with :ok <- verify_secret(secret),
         :ok <- verify_total(ttl),
         :ok <- verify_total_vs_required_shares(ttl, req) do
      %{
        params
        | shares: KeyX.generate_shares!(params.required_shares, params.total_shares, secret)
      }
    end
  end

  defp verify_secret(secret) do
    case not ConditionUtils.is_blank?(secret) do
      true -> :ok
      false -> {:error, :secret_is_empty}
    end
  end

  defp verify_total_vs_required_shares(total, required) do
    case total > required do
      true -> :ok
      false -> {:error, {:required_cannot_be_more_then_total, required, total}}
    end
  end

  defp verify_total(total) do
    case total > 1 do
      true -> :ok
      false -> {:total_cannot_be_less_then_2, total}
    end
  end

  def recover(shares) do
    KeyX.recover_secret(shares)
  end
end
