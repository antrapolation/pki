defmodule ExCcrypto.SecretSharing.ShamirContext do
  alias ExCcrypto.SecretSharing.ShamirContext
  use TypedStruct

  typedstruct do
    field(:algo, any(), default: :shamir)
    field(:total_share, any(), default: 3)
    field(:required_share, any(), default: 1)
    field(:session_data, map(), default: %{shares: []})
  end

  def set_algo_name(ctx, name), do: %ShamirContext{ctx | algo: name}

  def set_policy(_ctx, total, _required) when total < 1,
    do: {:error, {:total_cannot_be_negative_or_zero, total}}

  def set_policy(_ctx, _total, required) when required < 1,
    do: {:error, {:required_cannot_be_negative_or_zero, required}}

  def set_policy(_ctx, total, required) when required > total,
    do: {:error, {:required_is_more_than_total, total, required}}

  def set_policy(ctx, total, required) do
    %ShamirContext{ctx | total_share: total, required_share: required}
  end

  def add_share(ctx, share) when not is_list(share), do: add_share(ctx, [share])

  def add_share(ctx, share) do
    %ShamirContext{
      ctx
      | session_data: %{ctx.session_data | shares: ctx.session_data.shares ++ share}
    }
  end

  def get_shares(ctx), do: ctx.session_data.shares
end

defimpl ExCcrypto.SecretSharing, for: ExCcrypto.SecretSharing.ShamirContext do
  alias ExCcrypto.SecretSharing.ShamirContext

  def split(ctx, data, _opts) do
    {:ok, KeyX.generate_shares!(ctx.required_share, ctx.total_share, data)}
  end

  def recover_init(ctx, _opts) do
    ctx
  end

  def recover_add_share(_ctx, nil), do: {:error, :given_share_is_nil}
  def recover_add_share(_ctx, <<>>), do: {:error, :given_share_is_empty}

  def recover_add_share(ctx, share) do
    ShamirContext.add_share(ctx, share)
  end

  def recover_final(ctx) do
    # returns {:ok, value}
    IO.puts("recover : #{inspect(ctx)}")

    try do
      KeyX.recover_secret(ShamirContext.get_shares(ctx))
    rescue
      ArgumentError ->
        {:error, :given_shares_count_does_not_tally_with_split_policy}

      e in RuntimeError ->
        {:error, {:runtime_error, e.message}}
    end
  end
end

defimpl ExCcrypto.ContextConfig, for: ExCcrypto.SecretSharing.ShamirContext do
  alias ExCcrypto.SecretSharing.ShamirContext

  def set(ctx, :policy, value, _opts) do
    ShamirContext.set_policy(ctx, value.total, value.required)
  end

  def get(ctx, :policy, _default, _opts) do
    %{total: ctx.total_share, required: ctx.required_share}
  end

  def info(_ctx, :getter_key),
    do: %{
      policy:
        "Set the secret sharing policy in format %{total: <total share>, required: <required share>}"
    }

  def info(_ctx, :setter_key),
    do: %{
      policy:
        "Return the secret sharing policy in format %{total: <total share>, required: <required share>}"
    }

  def info(_ctx, info),
    do: %{error: "Info operation error on ShamirContext. No info key '#{info}' found"}
end
