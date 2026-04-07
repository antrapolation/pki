defmodule PkiValidation.Ocsp.RequestDecoder do
  @moduledoc """
  Decodes a DER-encoded `OCSPRequest` into a normalised Elixir map.

  The result shape is:

      %{cert_ids: [%{issuer_name_hash, issuer_key_hash, serial_number}, ...],
        nonce: binary() | nil}

  The compiled `:OCSP` Erlang module (see Task 1) provides the underlying
  ASN.1 codec. Because the local `OCSP.asn1` schema declares
  `AlgorithmIdentifier`, `Certificate`, and `Extensions` as `ANY`, the
  request extensions arrive as an opaque DER binary; we use
  `:public_key.der_decode/2` (which knows the full PKIX schema) to parse
  them and surface the OCSP nonce extension.

  Decode failures of any kind are surfaced as `{:error, :malformed}`.
  """

  # RFC 6960 §4.4.1
  @nonce_oid {1, 3, 6, 1, 5, 5, 7, 48, 1, 2}

  @doc """
  Decode a DER-encoded OCSPRequest.

  Returns `{:ok, %{cert_ids: [...], nonce: ...}}` on success or
  `{:error, :malformed}` for any decode failure.
  """
  @spec decode(binary()) :: {:ok, map()} | {:error, :malformed}
  def decode(der) when is_binary(der) and byte_size(der) > 0 do
    try do
      case :OCSP.decode(:OCSPRequest, der) do
        {:ok, {:OCSPRequest, tbs, _signature}} ->
          {:ok, parse_tbs(tbs)}

        {:error, _} ->
          {:error, :malformed}
      end
    rescue
      _ -> {:error, :malformed}
    catch
      _, _ -> {:error, :malformed}
    end
  end

  def decode(_), do: {:error, :malformed}

  # ---- Private ----

  defp parse_tbs({:TBSRequest, _version, _requestor, request_list, extensions}) do
    %{
      cert_ids: Enum.map(request_list, &cert_id_from_request/1),
      nonce: extract_nonce(extensions)
    }
  end

  defp cert_id_from_request({:Request, cert_id, _exts}) do
    {:CertID, _hash_alg, name_hash, key_hash, serial} = cert_id

    %{
      issuer_name_hash: name_hash,
      issuer_key_hash: key_hash,
      serial_number: serial
    }
  end

  defp extract_nonce(:asn1_NOVALUE), do: nil
  defp extract_nonce(nil), do: nil

  defp extract_nonce(extensions_der) when is_binary(extensions_der) do
    try do
      parsed = :public_key.der_decode(:Extensions, extensions_der)
      find_nonce(parsed)
    rescue
      _ -> nil
    catch
      _, _ -> nil
    end
  end

  defp extract_nonce(_), do: nil

  defp find_nonce(extensions) when is_list(extensions) do
    Enum.find_value(extensions, fn
      {:Extension, @nonce_oid, _critical, value} -> unwrap_octet_string(value)
      _ -> nil
    end)
  end

  defp find_nonce(_), do: nil

  # The OCSP nonce extension's extnValue is a DER OCTET STRING wrapping the
  # raw nonce bytes. Strip the tag/length to expose the inner nonce.
  defp unwrap_octet_string(<<0x04, len, rest::binary>>) when byte_size(rest) >= len do
    <<nonce::binary-size(len), _::binary>> = rest
    nonce
  end

  defp unwrap_octet_string(<<0x04, 0x81, len, rest::binary>>) when byte_size(rest) >= len do
    <<nonce::binary-size(len), _::binary>> = rest
    nonce
  end

  defp unwrap_octet_string(<<0x04, 0x82, len::16, rest::binary>>) when byte_size(rest) >= len do
    <<nonce::binary-size(len), _::binary>> = rest
    nonce
  end

  defp unwrap_octet_string(other) when is_binary(other), do: other
end
