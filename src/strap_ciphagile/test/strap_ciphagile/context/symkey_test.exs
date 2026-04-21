defmodule StrapCiphagile.Context.SymkeyTest do
  use ExUnit.Case
  alias StrapCiphagile.Context.Symkey
  alias StrapCiphagile.Context.KDF
  alias StrapCiphagile.EncoderProtocol
  alias StrapCiphagile.DecoderProtocol

  @test_dir "test_artifact"

  setup_all do
    {:ok, ap_java_crypto_pid} = ApJavaCrypto.start_link()
    Process.sleep(1000)
    File.mkdir_p!(@test_dir)
    %{run_id: nil, ap_java_crypto_pid: ap_java_crypto_pid}
  end

  # --- ARTIFACT GENERATOR ---

  test "generate symkey test artifacts for AES and ChaCha20", %{ap_java_crypto_pid: _pid} do
    generate_symkey()
  end

  defp save_artifact(format_name, input_map, encoded_output) do
    json_safe_map =
      Map.new(input_map, fn {k, v} ->
        safe_val = if is_binary(v), do: Base.encode64(v), else: v
        {k, safe_val}
      end)

    input_json = Jason.encode!(json_safe_map)
    output_hex = Base.encode16(encoded_output, case: :lower)

    File.write!(Path.join(@test_dir, "#{format_name}_input.json"), input_json)
    File.write!(Path.join(@test_dir, "#{format_name}_output.txt"), output_hex)
  end

  defp generate_symkey() do
    raw_key = :crypto.strong_rand_bytes(32)

    symkey = %Symkey{
      version: :v1_0,
      algo: :aes,
      variant: :aes_256,
      raw_key: raw_key
    }

    {:ok, encoded} = StrapCiphagile.encode(symkey)
    save_artifact("symkey_aes_256", %{key: raw_key}, encoded)

    raw_key_chacha = :crypto.strong_rand_bytes(32)

    symkey_chacha = %Symkey{
      version: :v1_0,
      algo: :chacha20,
      variant: :chacha20,
      raw_key: raw_key_chacha
    }

    {:ok, encoded_chacha} = StrapCiphagile.encode(symkey_chacha)
    save_artifact("symkey_chacha20", %{key: raw_key_chacha}, encoded_chacha)
  end

  # --- ARTIFACT VALIDATOR ---

  test "decode and validate symkey artifacts in test_artifact directory", %{
    ap_java_crypto_pid: _pid
  } do
    files = File.ls!(@test_dir)

    symkey_files =
      Enum.filter(
        files,
        &(String.starts_with?(&1, "symkey") && String.ends_with?(&1, "_input.json") &&
            !String.contains?(&1, "cipher"))
      )

    for input_file <- symkey_files do
      base_name = String.replace(input_file, "_input.json", "")
      output_file = "#{base_name}_output.txt"

      input_path = Path.join(@test_dir, input_file)
      output_path = Path.join(@test_dir, output_file)

      assert File.exists?(output_path), "Missing output file for #{input_file}"

      input_json = File.read!(input_path)
      output_hex = File.read!(output_path)

      input_data = Jason.decode!(input_json)
      {:ok, output_data} = Base.decode16(output_hex, case: :mixed)

      assert {:ok, decoded_struct} = StrapCiphagile.decode(output_data)

      input_data =
        Map.new(input_data, fn {k, v} ->
          case Base.decode64(v) do
            {:ok, decoded} -> {k, decoded}
            :error -> {k, v}
          end
        end)

      validate_symkey(decoded_struct, input_data)
    end
  end

  defp validate_symkey(%Symkey{} = symkey, input_data) do
    assert symkey.raw_key == input_data["key"]
  end

  test "encode and decode basic Symkey" do
    symkey = %Symkey{
      version: :v1_0,
      algo: :aes,
      variant: :aes_256,
      raw_key: :crypto.strong_rand_bytes(32)
    }

    assert {:ok, encoded} = EncoderProtocol.encode(symkey)
    # Check outer tag 0x10
    assert <<0x10, _rest::binary>> = encoded

    assert {:ok, decoded} = DecoderProtocol.decode(%Symkey{}, encoded)
    assert decoded.algo == :aes
    assert decoded.variant == :aes_256
  end

  test "encode and decode Symkey with RawKey" do
    key_bytes = :crypto.strong_rand_bytes(32)

    symkey = %Symkey{
      version: :v1_0,
      algo: :chacha20,
      variant: :chacha20,
      raw_key: key_bytes
    }

    assert {:ok, encoded} = EncoderProtocol.encode(symkey)
    assert {:ok, decoded} = DecoderProtocol.decode(%Symkey{}, encoded)

    assert decoded.algo == :chacha20
    assert decoded.variant == :chacha20
    assert decoded.raw_key == key_bytes
  end

  test "encode and decode Symkey with KDFConfig" do
    kdf =
      KDF.new()
      |> KDF.set_config(:pbkdf2, %{iteration: 1000, salt: "s", out_length: 16})
      |> Map.put(:input, "password")

    symkey = %Symkey{
      version: :v1_0,
      algo: :aes,
      variant: :aes_128,
      kdf_config: kdf
    }

    assert {:ok, encoded} = EncoderProtocol.encode(symkey)
    assert {:ok, decoded} = DecoderProtocol.decode(%Symkey{}, encoded)

    assert decoded.kdf_config != nil
    # Check that inner KDF was decoded correctly
    decoded_kdf = decoded.kdf_config
    assert decoded_kdf.variant == :pbkdf2
    assert decoded_kdf.input == "password"
  end

  test "StrapCiphagile dispatch for Symkey" do
    symkey = %Symkey{
      version: :v1_0,
      algo: :camelia,
      variant: :camelia_192
    }

    assert {:ok, encoded} =
             StrapCiphagile.encode(symkey)

    assert {:ok, decoded} = StrapCiphagile.decode(encoded)
    assert decoded.algo == :camelia
  end

  test "decoding various algos" do
    # Just spot check a few rare ones
    algos = [
      {:clefia, 0x03},
      {:seed, 0x04},
      {:height, 0x08},
      {:present, 0x09},
      {:deoxys_tbc, 0x10},
      {:skinny, 0x11},
      {:xts_aes, 0x12},
      {:hc, 0x21},
      {:kcipher_2, 0x22},
      {:mugi, 0x23},
      {:rabbit, 0x24}
    ]

    Enum.each(algos, fn {algo_atom, _byte} ->
      symkey = %Symkey{version: :v1_0, algo: algo_atom, variant: 1}
      {:ok, enc} = EncoderProtocol.encode(symkey)
      {:ok, dec} = DecoderProtocol.decode(%Symkey{}, enc)
      assert dec.algo == algo_atom
    end)
  end

  test "validate key size for AES" do
    # Valid AES-128 (16 bytes)
    symkey = %Symkey{
      version: :v1_0,
      algo: :aes,
      variant: :aes_128,
      raw_key: :binary.copy(<<0>>, 16)
    }

    assert {:ok, _} = EncoderProtocol.encode(symkey)

    # Invalid AES-128 (32 bytes)
    symkey_bad = %{symkey | raw_key: :binary.copy(<<0>>, 32)}
    assert {:error, {:invalid_key_size, :aes, :aes_128, 256}} = EncoderProtocol.encode(symkey_bad)
  end

  test "validate key size for ChaCha20" do
    # Valid (32 bytes)
    symkey = %Symkey{
      version: :v1_0,
      algo: :chacha20,
      variant: 1,
      raw_key: :binary.copy(<<0>>, 32)
    }

    assert {:ok, _} = EncoderProtocol.encode(symkey)

    # Invalid (16 bytes)
    symkey_bad = %{symkey | raw_key: :binary.copy(<<0>>, 16)}
    assert {:error, {:invalid_key_size, :chacha20, 1, 128}} = EncoderProtocol.encode(symkey_bad)
  end

  test "validate KDF output length matches Symkey variant" do
    # Valid: AES-128 (16 bytes) with KDF output 16
    kdf_valid =
      KDF.new()
      |> KDF.set_config(:pbkdf2, %{iteration: 1000, salt: "s", out_length: 16})

    symkey = %Symkey{
      version: :v1_0,
      algo: :aes,
      variant: :aes_128,
      kdf_config: kdf_valid
    }

    assert {:ok, _} = EncoderProtocol.encode(symkey)

    # Invalid: AES-128 (16 bytes) but KDF output 32
    kdf_invalid =
      KDF.new()
      |> KDF.set_config(:pbkdf2, %{iteration: 1000, salt: "s", out_length: 32})

    symkey_bad = %{symkey | kdf_config: kdf_invalid}
    assert {:error, :invalid_kdf_output_size} = EncoderProtocol.encode(symkey_bad)
  end

  test "validate KDF output length with mixed types" do
    # Hex String "0x10" -> 16
    kdf_hex =
      KDF.new()
      |> KDF.set_config(:pbkdf2, %{iteration: 1000, salt: "s", out_length: "0x10"})

    symkey_hex = %Symkey{
      version: :v1_0,
      algo: :aes,
      variant: :aes_128,
      kdf_config: kdf_hex
    }

    assert {:ok, _} = EncoderProtocol.encode(symkey_hex)

    # String "16" -> 16
    kdf_str =
      KDF.new()
      |> KDF.set_config(:pbkdf2, %{iteration: 1000, salt: "s", out_length: "16"})

    symkey_str = %Symkey{
      version: :v1_0,
      algo: :aes,
      variant: :aes_128,
      kdf_config: kdf_str
    }

    assert {:ok, _} = EncoderProtocol.encode(symkey_str)

    # Raw Binary <<16>> -> 16
    kdf_bin =
      KDF.new()
      |> KDF.set_config(:pbkdf2, %{iteration: 1000, salt: "s", out_length: <<16>>})

    symkey_bin = %Symkey{
      version: :v1_0,
      algo: :aes,
      variant: :aes_128,
      kdf_config: kdf_bin
    }

    assert {:ok, _} = EncoderProtocol.encode(symkey_bin)

    # Invalid Hex "0x20" -> 32
    kdf_bad =
      KDF.new()
      |> KDF.set_config(:pbkdf2, %{iteration: 1000, salt: "s", out_length: "0x20"})

    symkey_bad = %Symkey{
      version: :v1_0,
      algo: :aes,
      variant: :aes_128,
      kdf_config: kdf_bad
    }

    assert {:error, :invalid_kdf_output_size} = EncoderProtocol.encode(symkey_bad)
  end

  test "decode with random data at the back" do
    symkey = %Symkey{
      version: :v1_0,
      algo: :aes,
      variant: :aes_256,
      raw_key: :crypto.strong_rand_bytes(32)
    }

    {:ok, encoded} = EncoderProtocol.encode(symkey)
    random_garbage = :crypto.strong_rand_bytes(10)
    full_binary = encoded <> random_garbage

    # DecoderProtocol returns {:ok, {struct, rest}} if rest not empty
    assert {:ok, {decoded_key, rest}} = DecoderProtocol.decode(%Symkey{}, full_binary)
    assert decoded_key.algo == :aes
    assert decoded_key.variant == :aes_256
    assert rest == random_garbage
  end
end
