# Public API
defmodule ExCcrypto.Digest.DigestContextBuilder do
  alias ExCcrypto.Digest.DigestContextBuilder
  alias ExCcrypto.Digest.DigestContext

  def supported_digests() do
    Enum.sort(:crypto.supports(:hashs))
  end

  def digest_context(hash) do
    case Enum.member?(DigestContextBuilder.supported_digests(), hash) do
      true ->
        info = :crypto.hash_info(hash)
        construct_digest_context(hash, info)

      false ->
        {:error, {:digest_not_supported, hash}}
    end
  end

  defp construct_digest_context(hash, info) do
    %DigestContext{}
    |> DigestContext.set_digest_name(hash)
    |> DigestContext.set_output_byte_size(info.size)
    |> DigestContext.set_block_size(info.block_size)
  end
end
