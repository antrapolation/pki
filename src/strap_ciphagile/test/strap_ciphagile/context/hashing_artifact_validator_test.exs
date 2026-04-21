defmodule StrapCiphagile.Context.HashingArtifactValidatorTest do
  use ExUnit.Case
  alias StrapCiphagile.Context.Hashing
  alias StrapCiphagile.EncoderProtocol
  alias StrapCiphagile.DecoderProtocol

  @test_dir "test_artifact"

  setup_all do
    {:ok, ap_java_crypto_pid} = ApJavaCrypto.start_link()
    Process.sleep(1000)
    File.mkdir_p!(@test_dir)
    %{run_id: nil, ap_java_crypto_pid: ap_java_crypto_pid}
  end

  # --- ARTIFACT VALIDATOR ---

  test "decode and validate hashing artifacts in test_artifact directory", %{
    ap_java_crypto_pid: _pid
  } do
    files = File.ls!(@test_dir)

    hashing_files =
      Enum.filter(
        files,
        &(String.starts_with?(&1, "hashing") && String.ends_with?(&1, "_input.json"))
      )

    for input_file <- hashing_files do
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

      validate_hashing(decoded_struct, input_data)
    end
  end

  defp validate_hashing(%Hashing{} = hash, input_data) do
    target_data = input_data["data"] <> input_data["salt"]

    case hash.algo do
      :sha2 ->
        algo = map_sha2_variant(hash.variant)

        if algo == :skip do
          # SHA-512 truncated variants not supported by Erlang crypto, skip validation
          :ok
        else
          ctx = %ExCcrypto.Digest.DigestContext{algo: algo}
          {:ok, %{digested: actual_digest}} = ExCcrypto.Digest.digest(ctx, target_data)
          assert actual_digest == hash.digest
        end

      :sha3 ->
        algo = map_sha3_variant(hash.variant)

        if algo == :skip do
          # SHA3 truncated variants not supported by Erlang crypto, skip validation
          :ok
        else
          ctx = %ExCcrypto.Digest.DigestContext{algo: algo}
          {:ok, %{digested: actual_digest}} = ExCcrypto.Digest.digest(ctx, target_data)
          assert actual_digest == hash.digest
        end

      _ ->
        :ok
    end
  end

  defp map_sha2_variant(:sha2_256), do: :sha256
  defp map_sha2_variant(:sha2_224), do: :sha224
  defp map_sha2_variant(:sha2_384), do: :sha384
  defp map_sha2_variant(:sha2_512), do: :sha512
  # SHA-512 truncated variants are not supported by Erlang crypto, skip validation
  defp map_sha2_variant(:sha2_512_224), do: :skip
  defp map_sha2_variant(:sha2_512_256), do: :skip
  defp map_sha2_variant(variant), do: variant

  defp map_sha3_variant(:sha3_224), do: :sha3_224
  defp map_sha3_variant(:sha3_256), do: :sha3_256
  defp map_sha3_variant(:sha3_384), do: :sha3_384
  defp map_sha3_variant(:sha3_512), do: :sha3_512
  # SHA3 truncated variants not supported by Erlang crypto, skip validation
  defp map_sha3_variant(:sha3_512_224), do: :skip
  defp map_sha3_variant(:sha3_512_256), do: :skip
  defp map_sha3_variant(variant), do: variant
end
