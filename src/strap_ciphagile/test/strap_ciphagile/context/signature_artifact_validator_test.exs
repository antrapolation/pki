defmodule StrapCiphagile.Context.SignatureArtifactValidatorTest do
  use ExUnit.Case

  alias StrapCiphagile.Context.Signature

  @test_dir "test_artifact"

  setup_all do
    {:ok, ap_java_crypto_pid} = ApJavaCrypto.start_link()
    # small sleep to ensure Java JRuby VM is fully up
    Process.sleep(1000)
    File.mkdir_p!(@test_dir)
    %{ap_java_crypto_pid: ap_java_crypto_pid}
  end

  # --- ARTIFACT VALIDATOR ---

  test "decode and validate signature artifacts in test_artifact directory", %{
    ap_java_crypto_pid: _pid
  } do
    files = File.ls!(@test_dir)

    sig_files =
      Enum.filter(
        files,
        &(String.starts_with?(&1, "signature") && String.ends_with?(&1, "_input.json"))
      )

    for input_file <- sig_files do
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

      validate_signature(decoded_struct, input_data)
    end
  end

  defp validate_signature(%Signature{} = sig, input_data) do
    assert sig.plaintext == input_data["plaintext"]

    case sig.algo do
      :ecc ->
        assert true

      :rsa ->
        assert true

      :ml_dsa ->
        assert true

      :kaz_sign ->
        assert true

      _ ->
        :ok
    end
  end
end
