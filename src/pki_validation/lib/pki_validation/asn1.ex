defmodule PkiValidation.Asn1 do
  @moduledoc """
  Wrapper around the compiled OCSP ASN.1 module.

  The compiled module is named `:OCSP` (Erlang atom). This wrapper normalises
  the return shapes so callers always see `{:ok, binary}` or `{:error, reason}`.
  """

  @asn1_module :OCSP

  @doc """
  Encode an Erlang term into DER for the given ASN.1 type.

  Returns `{:ok, der_binary}` or `{:error, reason}`.
  """
  def encode(type, value) do
    case @asn1_module.encode(type, value) do
      {:ok, der} when is_binary(der) -> {:ok, der}
      {:ok, iolist} -> {:ok, IO.iodata_to_binary(iolist)}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Decode a DER binary into an Erlang term for the given ASN.1 type.

  Returns `{:ok, value}` or `{:error, reason}`.
  """
  def decode(type, der) when is_binary(der) do
    case @asn1_module.decode(type, der) do
      {:ok, value} -> {:ok, value}
      {:error, reason} -> {:error, reason}
    end
  end
end
