defmodule StrapCiphagile.Context.SymkeyCipherArtifactValidatorTest do
  use ExUnit.Case

  alias StrapCiphagile.Context.SymkeyCipher

  alias ExCcrypto.Cipher.CipherContextBuilder
  alias ExCcrypto.Cipher

  @test_dir "test_artifact"

  setup_all do
    {:ok, ap_java_crypto_pid} = ApJavaCrypto.start_link()
    Process.sleep(1000)
    File.mkdir_p!(@test_dir)
    %{run_id: nil, ap_java_crypto_pid: ap_java_crypto_pid}
  end

  # --- ARTIFACT VALIDATOR ---

  test "decode and validate symkey_cipher artifacts in test_artifact directory", %{
    ap_java_crypto_pid: _pid
  } do
    files = File.ls!(@test_dir)

    cipher_files =
      Enum.filter(
        files,
        &(String.starts_with?(&1, "symkey_cipher") && String.ends_with?(&1, "_input.json"))
      )

    for input_file <- cipher_files do
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

      # Handle nil values in input data (JSON null -> nil)
      input_data =
        Map.new(input_data, fn {k, v} ->
          if is_nil(v) do
            {k, nil}
          else
            case Base.decode64(v) do
              {:ok, decoded} -> {k, decoded}
              :error -> {k, v}
            end
          end
        end)

      validate_symkey_cipher(decoded_struct, input_data)
    end
  end

  defp validate_symkey_cipher(%SymkeyCipher{} = symkey_cipher, input_data) do
    case symkey_cipher.symkey.algo do
      :aes ->
        # Build cipher variant based on actual variant in artifact
        variant = symkey_cipher.symkey.variant
        mode = symkey_cipher.mode
        cipher_variant = String.to_atom("#{variant}_#{mode}")

        ctx =
          CipherContextBuilder.cipher_context(cipher_variant)
          |> ExCcrypto.ContextConfig.set(:session_key, symkey_cipher.symkey.raw_key)
          |> ExCcrypto.ContextConfig.set(:cipher_ops, :decrypt)

        # Only set IV if present
        ctx =
          if symkey_cipher.iv && byte_size(symkey_cipher.iv) > 0 do
            ExCcrypto.ContextConfig.set(ctx, :iv, symkey_cipher.iv)
          else
            ctx
          end

        # Only set tag for AEAD ciphers (GCM)
        ctx =
          if symkey_cipher.tag && byte_size(symkey_cipher.tag) > 0 do
            ExCcrypto.ContextConfig.set(ctx, :tag, symkey_cipher.tag)
          else
            ctx
          end

        # Check if context creation succeeded
        case ctx do
          {:error, _reason} ->
            IO.puts("Skipping validation for unsupported cipher: #{cipher_variant}")
            :ok

          _ ->
            assert dec_ctx = Cipher.cipher_init(ctx, %{operation: :decrypt})
            dec_ctx = Cipher.cipher_update(dec_ctx, symkey_cipher.cipher)
            assert {:ok, decrypted} = Cipher.cipher_final(dec_ctx)
            assert decrypted == input_data["plaintext"]
        end

      _ ->
        :ok
    end
  end
end
