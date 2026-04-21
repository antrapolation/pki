defmodule StrapCiphagile.Context.SymkeyArtifactGeneratorTest do
  use ExUnit.Case
  alias StrapCiphagile.Context.Symkey

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
end
