import Bitwise

defmodule StrapCiphagile.VarLengthData do
  def encode(data) when is_binary(data) and byte_size(data) > 0 do
    size = byte_size(data)

    res =
      cond do
        size < 2 ** (2 <<< 2) ->
          {:ok, [0x01, size]}

        size >= 2 ** (2 <<< 2) and size < 2 ** (2 <<< 3) ->
          <<b1::8, b2::8>> = <<size::16>>
          {:ok, [0x02, b1, b2]}

        size >= 2 ** (2 <<< 3) and size < 2 ** (2 <<< 4) ->
          <<b1::8, b2::8, b3::8>> = <<size::24>>
          {:ok, [0x03, b1, b2, b3]}

        size >= 2 ** (2 <<< 4) and size < 2 ** (2 <<< 5) ->
          <<b1::8, b2::8, b3::8, b4::8>> = <<size::32>>
          {:ok, [0x04, b1, b2, b3, b4]}

        true ->
          {:error, {:unsupported_size, size}}
      end

    append_data(res, data)
  end

  def encode(nil), do: {:ok, <<>>}
  def encode(""), do: {:ok, <<>>}
  def encode(_), do: {:error, :invalid_data}

  @doc """
  Decodes variable length data from binary.
  Returns {:ok, data, rest} or {:error, reason}
  """
  def decode(<<0x01, len::8, data::binary-size(len), rest::binary>>), do: {:ok, data, rest}

  def decode(<<0x02, len::16, data::binary-size(len), rest::binary>>), do: {:ok, data, rest}

  def decode(<<0x03, len::24, data::binary-size(len), rest::binary>>), do: {:ok, data, rest}

  def decode(<<0x04, len::32, data::binary-size(len), rest::binary>>), do: {:ok, data, rest}

  # Treat 0x01, 0x00 as empty/nil? No, format says:
  # 0x01 = length value is 1 byte long.
  # So 0 bytes data with 1 byte length value 0: <<0x01, 0x00>> -> ""
  def decode(<<0x01, 0x00, rest::binary>>), do: {:ok, "", rest}

  # Fallback for empty/nil if we decide a specific byte means nil without length spec,
  # but spec implies length spec always exists if data exists.
  # If we treat empty binary as valid no-op for optional fields that might be handled at higher level.
  # For now sticking to spec:
  def decode(bin), do: {:error, {:invalid_var_length_data, bin}}

  defp append_data({:ok, res}, data), do: {:ok, IO.iodata_to_binary(res ++ [data])}
  defp append_data({:error, _} = err, _), do: err
end
