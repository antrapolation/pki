defmodule ExCcrypto.Mac.MacContextBuilder do
  alias ExCcrypto.Mac.MacContextBuilder
  alias ExCcrypto.ContextConfig
  alias ExCcrypto.Mac.MacContext
  alias ExCcrypto.Cipher.CipherContextBuilder
  alias ExCcrypto.Digest.DigestContextBuilder

  def mac_context(algo, key \\ nil)

  def mac_context(algo, <<>>), do: mac_context(algo, nil)

  def mac_context(:poly1305, nil) do
    # 32 bytes key / 16 bytes MAC output
    %MacContext{}
    |> MacContext.set_type(:poly1305)
    |> MacContext.set_key_byte_size(32)
  end

  def mac_context(algo, nil) do
    cond do
      Enum.member?(MacContextBuilder.supported_digest_algos(), algo) == true ->
        dinfo = DigestContextBuilder.digest_context(algo)

        %MacContext{}
        |> MacContext.set_type(:hmac, algo)
        |> MacContext.set_key_byte_size(ContextConfig.get(dinfo, :output_byte_size))

      Enum.member?(MacContextBuilder.supported_cipher_algos(), algo) == true ->
        cinfo = CipherContextBuilder.cipher_context(algo)

        %MacContext{}
        |> MacContext.set_type(:cmac, algo)
        |> MacContext.set_key_byte_size(ContextConfig.get(cinfo, :key_byte_size))

      true ->
        {:error, {:given_algo_not_supported_for_mac_operation, algo}}
    end
  end

  def mac_context(algo, key) do
    ctx = mac_context(algo, nil)

    case byte_size(key) == ctx.key_byte_size do
      true ->
        MacContext.set_key(ctx, key)

      false ->
        {:error, {:given_key_size_does_not_match_spec, byte_size(key), ctx.key_byte_size}}
    end
  end

  def supported_cipher_algos() do
    Enum.reject(CipherContextBuilder.supported_ciphers(), fn c ->
      not String.ends_with?(to_string(c), "cbc")
    end)
  end

  def supported_digest_algos() do
    Enum.reject(DigestContextBuilder.supported_digests(), fn d ->
      case d do
        x when x in [:shake128, :shake256] -> true
        _ -> false
      end
    end)
  end
end
