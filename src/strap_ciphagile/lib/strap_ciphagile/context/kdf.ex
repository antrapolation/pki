# tag 0x01
defmodule StrapCiphagile.Context.Argon2Config do
  use TypedStruct

  typedstruct do
    field(:iteration, any())
    field(:cost, any())
    field(:parallel, any())
    # TLV encode
    field(:salt, any())
    # TLV encode
    field(:out_length, any())
    # TLV 0xF0
    field(:misc, any())
  end
end

# tag 0x02
defmodule StrapCiphagile.Context.PBKDF2Config do
  use TypedStruct

  typedstruct do
    field(:iteration, any())
    # TLV encode
    field(:salt, any())
    # TLV encode
    field(:out_length, any())
    # TLV 0xF0
    field(:misc, any())
  end
end

# tag 0x03
defmodule StrapCiphagile.Context.BCryptConfig do
  use TypedStruct

  typedstruct do
    field(:cost, any())
    # TLV encode
    field(:salt, any())
    # TLV encode
    field(:out_length, any())
    # TLV 0xF0
    field(:misc, any())
  end
end

# tag 0x04
defmodule StrapCiphagile.Context.ScryptConfig do
  use TypedStruct

  typedstruct do
    field(:cost, any())
    field(:parallel, any())
    field(:blocksize, any())
    # TLV encode
    field(:salt, any())
    # TLV encode
    field(:out_length, any())
    # TLV 0xF0
    field(:misc, any())
  end
end

defmodule StrapCiphagile.Context.KDF do
  use TypedStruct
  alias StrapCiphagile.Context.{Argon2Config, PBKDF2Config, BCryptConfig, ScryptConfig}

  typedstruct do
    field(:version, any(), default: :v1_0)
    field(:algo, any(), default: :kdf)
    field(:variant, any())
    # anyone of the options above: Argon2Config, PBKDF2Config, ScryptConfig, BCryptConfig
    field(:kdf_config, any())
    # optional
    field(:output, any())
    field(:input, any())
    # TLV 0xF0
    field(:misc, any())
  end

  def normalize_int_field(val) when is_integer(val), do: :binary.encode_unsigned(val)

  def normalize_int_field("0x" <> hex_str),
    do: hex_str |> String.to_integer(16) |> :binary.encode_unsigned()

  def normalize_int_field(val) when is_binary(val) do
    case Integer.parse(val) do
      {int, ""} -> :binary.encode_unsigned(int)
      _ -> val
    end
  end

  def normalize_int_field(val), do: val

  def new(opts \\ []) do
    struct(__MODULE__, opts)
  end

  def set_config(%__MODULE__{} = kdf, :argon2, params) do
    config = struct(Argon2Config, params)
    %{kdf | variant: :argon2, kdf_config: config}
  end

  def set_config(%__MODULE__{} = kdf, :pbkdf2, params) do
    config = struct(PBKDF2Config, params)
    %{kdf | variant: :pbkdf2, kdf_config: config}
  end

  def set_config(%__MODULE__{} = kdf, :bcrypt, params) do
    config = struct(BCryptConfig, params)
    %{kdf | variant: :bcrypt, kdf_config: config}
  end

  def set_config(%__MODULE__{} = kdf, :scrypt, params) do
    config = struct(ScryptConfig, params)
    %{kdf | variant: :scrypt, kdf_config: config}
  end
end

alias StrapCiphagile.EncoderProtocol
alias StrapCiphagile.DecoderProtocol
alias StrapCiphagile.VarLengthData
alias StrapCiphagile.Context.KDF
alias StrapCiphagile.Context.Argon2Config
alias StrapCiphagile.Context.PBKDF2Config
alias StrapCiphagile.Context.ScryptConfig
alias StrapCiphagile.Context.BCryptConfig

defimpl EncoderProtocol, for: KDF do
  alias StrapCiphagile.Tags

  def encode(%KDF{} = kdf, _opts) do
    with {:ok, version_byte} <- encode_version(kdf.version),
         {:ok, algo_byte} <- encode_algo(kdf.algo),
         {:ok, variant_byte} <- encode_variant(kdf.variant),
         {:ok, config_bin} <- encode_config(kdf.variant, kdf.kdf_config),
         {:ok, input_bin} <- encode_tlv(0x11, kdf.input),
         {:ok, output_bin} <- encode_tlv(0x10, kdf.output),
         {:ok, misc_bin} <- encode_tlv(0xF0, kdf.misc) do
      content =
        <<version_byte, algo_byte, variant_byte>> <>
          config_bin <> input_bin <> output_bin <> misc_bin

      with {:ok, full_data} <- VarLengthData.encode(content),
           {:ok, tag} <- Tags.tag_value(:kdf_envp) do
        {:ok, <<tag>> <> full_data}
      else
        err -> err
      end
    else
      err -> err
    end
  end

  defp encode_version(:v1_0), do: {:ok, 0x01}
  defp encode_version(_), do: {:error, :unsupported_version}

  defp encode_algo(:kdf), do: {:ok, 0x02}
  defp encode_algo(_), do: {:error, :unsupported_algo}

  defp encode_variant(:argon2), do: {:ok, 0x01}
  defp encode_variant(:pbkdf2), do: {:ok, 0x02}
  defp encode_variant(:bcrypt), do: {:ok, 0x03}
  defp encode_variant(:scrypt), do: {:ok, 0x04}
  defp encode_variant(_), do: {:error, :unknown_variant}

  defp encode_config(:argon2, map) when is_map(map) and not is_struct(map),
    do: encode_config_tlv(0x01, struct(Argon2Config, map))

  defp encode_config(:pbkdf2, map) when is_map(map) and not is_struct(map),
    do: encode_config_tlv(0x02, struct(PBKDF2Config, map))

  defp encode_config(:bcrypt, map) when is_map(map) and not is_struct(map),
    do: encode_config_tlv(0x03, struct(BCryptConfig, map))

  defp encode_config(:scrypt, map) when is_map(map) and not is_struct(map),
    do: encode_config_tlv(0x04, struct(ScryptConfig, map))

  defp encode_config(_, %Argon2Config{} = cfg), do: encode_config_tlv(0x01, cfg)
  defp encode_config(_, %PBKDF2Config{} = cfg), do: encode_config_tlv(0x02, cfg)
  defp encode_config(_, %BCryptConfig{} = cfg), do: encode_config_tlv(0x03, cfg)
  defp encode_config(_, %ScryptConfig{} = cfg), do: encode_config_tlv(0x04, cfg)
  defp encode_config(_, _), do: {:error, :unknown_kdf_config}

  defp encode_config_tlv(tag, config) do
    with {:ok, val} <- EncoderProtocol.encode(config) do
      with {:ok, encoded_val} <- VarLengthData.encode(val) do
        {:ok, <<tag>> <> encoded_val}
      else
        err -> err
      end
    else
      err -> err
    end
  end

  defp encode_tlv(_tag, nil), do: {:ok, <<>>}
  defp encode_tlv(_tag, ""), do: {:ok, <<>>}

  defp encode_tlv(tag, val) do
    with {:ok, encoded} <- VarLengthData.encode(val) do
      {:ok, <<tag>> <> encoded}
    else
      err -> err
    end
  end
end

defimpl EncoderProtocol, for: Argon2Config do
  def encode(cfg, _opts) do
    with {:ok, iter} <- VarLengthData.encode(KDF.normalize_int_field(cfg.iteration)),
         {:ok, cost} <- VarLengthData.encode(KDF.normalize_int_field(cfg.cost)),
         {:ok, parallel} <- VarLengthData.encode(KDF.normalize_int_field(cfg.parallel)),
         {:ok, salt} <- encode_tlv(0x01, cfg.salt),
         {:ok, len} <- encode_tlv(0x02, KDF.normalize_int_field(cfg.out_length)),
         {:ok, misc} <- encode_tlv(0xF0, cfg.misc) do
      {:ok, iter <> cost <> parallel <> salt <> len <> misc}
    else
      err -> err
    end
  end

  defp encode_tlv(_tag, nil), do: {:ok, <<>>}
  defp encode_tlv(_tag, ""), do: {:ok, <<>>}

  defp encode_tlv(tag, val) do
    with {:ok, enc} <- VarLengthData.encode(val), do: {:ok, <<tag>> <> enc}
  end
end

defimpl EncoderProtocol, for: PBKDF2Config do
  def encode(cfg, _opts) do
    with {:ok, iter} <- VarLengthData.encode(KDF.normalize_int_field(cfg.iteration)),
         {:ok, salt} <- encode_tlv(0x01, cfg.salt),
         {:ok, len} <- encode_tlv(0x02, KDF.normalize_int_field(cfg.out_length)),
         {:ok, misc} <- encode_tlv(0xF0, cfg.misc) do
      {:ok, iter <> salt <> len <> misc}
    else
      err -> err
    end
  end

  defp encode_tlv(_tag, nil), do: {:ok, <<>>}
  defp encode_tlv(_tag, ""), do: {:ok, <<>>}

  defp encode_tlv(tag, val) do
    with {:ok, enc} <- VarLengthData.encode(val), do: {:ok, <<tag>> <> enc}
  end
end

defimpl EncoderProtocol, for: BCryptConfig do
  def encode(cfg, _opts) do
    with {:ok, cost} <- VarLengthData.encode(KDF.normalize_int_field(cfg.cost)),
         {:ok, salt} <- encode_tlv(0x01, cfg.salt),
         {:ok, len} <- encode_tlv(0x02, KDF.normalize_int_field(cfg.out_length)),
         {:ok, misc} <- encode_tlv(0xF0, cfg.misc) do
      {:ok, cost <> salt <> len <> misc}
    else
      err -> err
    end
  end

  defp encode_tlv(_tag, nil), do: {:ok, <<>>}
  defp encode_tlv(_tag, ""), do: {:ok, <<>>}

  defp encode_tlv(tag, val) do
    with {:ok, enc} <- VarLengthData.encode(val), do: {:ok, <<tag>> <> enc}
  end
end

defimpl EncoderProtocol, for: ScryptConfig do
  def encode(cfg, _opts) do
    with {:ok, cost} <- VarLengthData.encode(KDF.normalize_int_field(cfg.cost)),
         {:ok, parallel} <- VarLengthData.encode(KDF.normalize_int_field(cfg.parallel)),
         {:ok, block} <- VarLengthData.encode(KDF.normalize_int_field(cfg.blocksize)),
         {:ok, salt} <- encode_tlv(0x01, cfg.salt),
         {:ok, len} <- encode_tlv(0x02, KDF.normalize_int_field(cfg.out_length)),
         {:ok, misc} <- encode_tlv(0xF0, cfg.misc) do
      {:ok, cost <> parallel <> block <> salt <> len <> misc}
    else
      err -> err
    end
  end

  defp encode_tlv(_tag, nil), do: {:ok, <<>>}
  defp encode_tlv(_tag, ""), do: {:ok, <<>>}

  defp encode_tlv(tag, val) do
    with {:ok, enc} <- VarLengthData.encode(val), do: {:ok, <<tag>> <> enc}
  end
end

defimpl DecoderProtocol, for: KDF do
  def decode(%KDF{} = _ctx, bin, _opts) do
    with <<0x02, rest_after_tag::binary>> <- bin,
         {:ok, kdf_content, outer_rest} <- VarLengthData.decode(rest_after_tag),
         <<version_byte, algo_byte, variant_byte, inner_rest::binary>> <- kdf_content,
         {:ok, version} <- decode_version(version_byte),
         {:ok, algo} <- decode_algo(algo_byte),
         {:ok, variant} <- decode_variant(variant_byte),
         {:ok, kdf_struct} <-
           decode_tlv(inner_rest, %KDF{version: version, algo: algo, variant: variant}) do
      if outer_rest == "" do
        {:ok, kdf_struct}
      else
        {:ok, {kdf_struct, outer_rest}}
      end
    else
      _ -> {:error, :decoding_failed}
    end
  end

  defp decode_version(0x01), do: {:ok, :v1_0}
  defp decode_version(_), do: {:error, :unknown_version}

  defp decode_algo(0x02), do: {:ok, :kdf}
  defp decode_algo(_), do: {:error, :unknown_algo}

  defp decode_variant(0x01), do: {:ok, :argon2}
  defp decode_variant(0x02), do: {:ok, :pbkdf2}
  defp decode_variant(0x03), do: {:ok, :bcrypt}
  defp decode_variant(0x04), do: {:ok, :scrypt}
  defp decode_variant(_), do: {:error, :unknown_variant}

  defp decode_tlv(<<>>, acc), do: {:ok, acc}

  # Config Tags
  # Argon2 (0x01)
  defp decode_tlv(<<0x01, rest::binary>>, acc) do
    with {:ok, content, rest_after} <- VarLengthData.decode(rest),
         {:ok, config} <- DecoderProtocol.decode(%Argon2Config{}, content) do
      decode_tlv(rest_after, %{acc | kdf_config: config})
    end
  end

  # PBKDF2 (0x02)
  defp decode_tlv(<<0x02, rest::binary>>, acc) do
    with {:ok, content, rest_after} <- VarLengthData.decode(rest),
         {:ok, config} <- DecoderProtocol.decode(%PBKDF2Config{}, content) do
      decode_tlv(rest_after, %{acc | kdf_config: config})
    end
  end

  # BCrypt (0x03)
  defp decode_tlv(<<0x03, rest::binary>>, acc) do
    with {:ok, content, rest_after} <- VarLengthData.decode(rest),
         {:ok, config} <- DecoderProtocol.decode(%BCryptConfig{}, content) do
      decode_tlv(rest_after, %{acc | kdf_config: config})
    end
  end

  # Scrypt (0x04)
  defp decode_tlv(<<0x04, rest::binary>>, acc) do
    with {:ok, content, rest_after} <- VarLengthData.decode(rest),
         {:ok, config} <- DecoderProtocol.decode(%ScryptConfig{}, content) do
      decode_tlv(rest_after, %{acc | kdf_config: config})
    end
  end

  # Optional Fields
  defp decode_tlv(<<0x10, rest::binary>>, acc) do
    case VarLengthData.decode(rest) do
      {:ok, val, rest_after} -> decode_tlv(rest_after, %{acc | output: val})
      err -> err
    end
  end

  defp decode_tlv(<<0x11, rest::binary>>, acc) do
    case VarLengthData.decode(rest) do
      {:ok, val, rest_after} -> decode_tlv(rest_after, %{acc | input: val})
      err -> err
    end
  end

  defp decode_tlv(<<0xF0, rest::binary>>, acc) do
    case VarLengthData.decode(rest) do
      {:ok, val, rest_after} -> decode_tlv(rest_after, %{acc | misc: val})
      err -> err
    end
  end

  defp decode_tlv(_, _), do: {:error, :invalid_tlv}
end

defimpl DecoderProtocol, for: Argon2Config do
  def decode(%Argon2Config{} = init, bin, _opts) do
    with {:ok, iter, r1} <- VarLengthData.decode(bin),
         {:ok, cost, r2} <- VarLengthData.decode(r1),
         {:ok, parallel, r3} <- VarLengthData.decode(r2),
         {:ok, new_struct} <-
           decode_tlv(r3, %{init | iteration: iter, cost: cost, parallel: parallel}) do
      {:ok, new_struct}
    end
  end

  defp decode_tlv(<<>>, acc), do: {:ok, acc}

  defp decode_tlv(<<0x01, rest::binary>>, acc) do
    {:ok, val, r} = VarLengthData.decode(rest)
    decode_tlv(r, %{acc | salt: val})
  end

  defp decode_tlv(<<0x02, rest::binary>>, acc) do
    {:ok, val, r} = VarLengthData.decode(rest)
    decode_tlv(r, %{acc | out_length: val})
  end

  defp decode_tlv(<<0xF0, rest::binary>>, acc) do
    {:ok, val, r} = VarLengthData.decode(rest)
    decode_tlv(r, %{acc | misc: val})
  end

  defp decode_tlv(_, acc), do: {:ok, acc}
end

defimpl DecoderProtocol, for: PBKDF2Config do
  def decode(%PBKDF2Config{} = init, bin, _opts) do
    with {:ok, iter, r1} <- VarLengthData.decode(bin),
         {:ok, new_struct} <- decode_tlv(r1, %{init | iteration: iter}) do
      {:ok, new_struct}
    end
  end

  defp decode_tlv(<<>>, acc), do: {:ok, acc}

  defp decode_tlv(<<0x01, rest::binary>>, acc) do
    {:ok, val, r} = VarLengthData.decode(rest)
    decode_tlv(r, %{acc | salt: val})
  end

  defp decode_tlv(<<0x02, rest::binary>>, acc) do
    {:ok, val, r} = VarLengthData.decode(rest)
    decode_tlv(r, %{acc | out_length: val})
  end

  defp decode_tlv(<<0xF0, rest::binary>>, acc) do
    {:ok, val, r} = VarLengthData.decode(rest)
    decode_tlv(r, %{acc | misc: val})
  end

  defp decode_tlv(_, acc), do: {:ok, acc}
end

defimpl DecoderProtocol, for: BCryptConfig do
  def decode(%BCryptConfig{} = init, bin, _opts) do
    with {:ok, cost, r1} <- VarLengthData.decode(bin),
         {:ok, new_struct} <- decode_tlv(r1, %{init | cost: cost}) do
      {:ok, new_struct}
    end
  end

  defp decode_tlv(<<>>, acc), do: {:ok, acc}

  defp decode_tlv(<<0x01, rest::binary>>, acc) do
    {:ok, val, r} = VarLengthData.decode(rest)
    decode_tlv(r, %{acc | salt: val})
  end

  defp decode_tlv(<<0x02, rest::binary>>, acc) do
    {:ok, val, r} = VarLengthData.decode(rest)
    decode_tlv(r, %{acc | out_length: val})
  end

  defp decode_tlv(<<0xF0, rest::binary>>, acc) do
    {:ok, val, r} = VarLengthData.decode(rest)
    decode_tlv(r, %{acc | misc: val})
  end

  defp decode_tlv(_, acc), do: {:ok, acc}
end

defimpl DecoderProtocol, for: ScryptConfig do
  def decode(%ScryptConfig{} = init, bin, _opts) do
    with {:ok, cost, r1} <- VarLengthData.decode(bin),
         {:ok, parallel, r2} <- VarLengthData.decode(r1),
         {:ok, block, r3} <- VarLengthData.decode(r2),
         {:ok, new_struct} <-
           decode_tlv(r3, %{init | cost: cost, parallel: parallel, blocksize: block}) do
      {:ok, new_struct}
    end
  end

  defp decode_tlv(<<>>, acc), do: {:ok, acc}

  defp decode_tlv(<<0x01, rest::binary>>, acc) do
    {:ok, val, r} = VarLengthData.decode(rest)
    decode_tlv(r, %{acc | salt: val})
  end

  defp decode_tlv(<<0x02, rest::binary>>, acc) do
    {:ok, val, r} = VarLengthData.decode(rest)
    decode_tlv(r, %{acc | out_length: val})
  end

  defp decode_tlv(<<0xF0, rest::binary>>, acc) do
    {:ok, val, r} = VarLengthData.decode(rest)
    decode_tlv(r, %{acc | misc: val})
  end

  defp decode_tlv(_, acc), do: {:ok, acc}
end
