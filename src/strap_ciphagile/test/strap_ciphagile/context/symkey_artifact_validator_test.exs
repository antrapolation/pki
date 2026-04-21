defmodule StrapCiphagile.Context.SymkeyArtifactValidatorTest do
  use ExUnit.Case
  alias StrapCiphagile.Context.Symkey

  @test_dir "test_artifact"

  setup_all do
    {:ok, ap_java_crypto_pid} = ApJavaCrypto.start_link()
    Process.sleep(1000)
    File.mkdir_p!(@test_dir)
    %{run_id: nil, ap_java_crypto_pid: ap_java_crypto_pid}
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
end
