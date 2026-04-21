defmodule ExCcrypto.Digest.DigestContext do
  alias ExCcrypto.Digest.DigestContext
  use TypedStruct

  typedstruct do
    field(:algo, atom())
    field(:output_byte_size, any())
    field(:block_size, any())
    field(:session_data, map(), default: %{output_format: :bin})
  end

  def set_digest_name(ctx, name), do: %DigestContext{ctx | algo: name}
  def get_digest_name(ctx), do: ctx.algo

  def set_output_byte_size(ctx, size), do: %DigestContext{ctx | output_byte_size: size}
  def get_output_byte_size(ctx), do: ctx.output_byte_size

  def set_block_size(ctx, size), do: %DigestContext{ctx | block_size: size}
  def get_block_size(ctx), do: ctx.block_size

  def set_digest_session(ctx, session)
      when is_map(ctx.session_data) and not is_map_key(ctx.session_data, :dgst_session) do
    %DigestContext{ctx | session_data: Map.put_new(ctx.session_data, :dgst_session, session)}
  end

  def set_digest_session(ctx, session) do
    %DigestContext{ctx | session_data: Map.put(ctx.session_data, :dgst_session, session)}
  end

  # do: %DigestContext{ctx | session_data: Map.put_new(ctx.session_data, :dgst_session, session)}

  def get_digest_session(ctx), do: ctx.session_data[:dgst_session]

  def remove_digest_session(ctx) do
    %DigestContext{ctx | session_data: Map.delete(ctx.session_data, :dgst_session)}
  end

  def set_output_format(ctx, format),
    do: %DigestContext{ctx | session_data: %{ctx.session_data | output_format: format}}
end

defimpl ExCcrypto.Digest, for: ExCcrypto.Digest.DigestContext do
  alias ExCcrypto.Digest.DigestResult
  alias ExCcrypto.Digest
  alias ExCcrypto.Digest.DigestContext

  def digest_init(ctx, _opts) do
    DigestContext.set_digest_session(ctx, :crypto.hash_init(ctx.algo))
  end

  def digest_update(ctx, data) do
    DigestContext.set_digest_session(
      ctx,
      :crypto.hash_update(DigestContext.get_digest_session(ctx), data)
    )
  end

  def digest_final(ctx) do
    dgst = :crypto.hash_final(DigestContext.get_digest_session(ctx))

    # {:ok,
    # %{digested: format_output(ctx, dgst), context: DigestContext.remove_digest_session(ctx)}}

    {:ok,
     %DigestResult{}
     |> DigestResult.set_digested_value(format_output(ctx, dgst))
     |> DigestResult.set_digest_context(DigestContext.remove_digest_session(ctx))}
  end

  def digest(ctx, data, opts) do
    Digest.digest_init(ctx, opts)
    |> Digest.digest_update(data)
    |> Digest.digest_final()
  end

  def digest_match?(ctx, data, dgst, opts) do
    with {:ok, %{digested: val}} <- Digest.digest(ctx, data, opts) do
      val == dgst
    else
      _ -> false
    end
  end

  defp format_output(%DigestContext{session_data: %{output_format: :bin}}, dgst), do: dgst

  defp format_output(%DigestContext{session_data: %{output_format: :hex}}, dgst),
    do: Base.encode16(dgst)

  defp format_output(%DigestContext{session_data: %{output_format: :b64}}, dgst),
    do: Base.encode64(dgst)

  defp format_output(%DigestContext{session_data: %{output_format: format}}, _dgst),
    do: {:error, {:unsupported_output_format, format}}
end

defimpl ExCcrypto.ContextConfig, for: ExCcrypto.Digest.DigestContext do
  alias ExCcrypto.Digest.DigestContext
  def set(ctx, :output_format, value, _opts), do: DigestContext.set_output_format(ctx, value)
  def set(ctx, _key, _value, _opts), do: ctx

  def get(ctx, :output_byte_size, _default, _opts), do: ctx.output_byte_size
  def get(ctx, :output_format, _default, _opts), do: ctx.output_format
  def get(_ctx, key, _default, _opts), do: {:error, {:unknown_key, key}}

  def info(_ctx, :getter_key),
    do: %{
      output_byte_size: "Return output size in bytes unit",
      output_format: "Return output format"
    }

  def info(_ctx, :setter_key),
    do: %{
      output_format:
        "Set the output format of this digest. Default is :bin. Other options including: :hex/:b64"
    }

  def info(_ctx, info),
    do: %{error: "Info operation error on DigestContext. No info key '#{info}' found"}
end
