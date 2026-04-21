defmodule StrapCiphagile.Context.SymkeyCipherArtifactGeneratorTest do
  use ExUnit.Case

  alias StrapCiphagile.Context.SymkeyCipher
  alias StrapCiphagile.Context.Symkey

  alias ExCcrypto.Cipher.CipherContextBuilder
  alias ExCcrypto.Cipher
  alias ExCcrypto.ContextConfig

  @test_dir "test_artifact"

  setup_all do
    {:ok, ap_java_crypto_pid} = ApJavaCrypto.start_link()
    Process.sleep(1000)
    File.mkdir_p!(@test_dir)
    %{run_id: nil, ap_java_crypto_pid: ap_java_crypto_pid}
  end

  # --- ARTIFACT GENERATOR ---

  # All available symmetric key algorithms from ex_ccrypto
  # AES: 128/192/256 with CBC/GCM/XTS modes
  # Camellia: 128/192/256 with CBC/GCM/XTS modes
  # ChaCha20-Poly1305

  @aes_vectors (for size <- [128, 192, 256], mode <- [:cbc, :gcm, :xts] do
                  %{
                    name: "AES-#{size}-#{String.upcase(to_string(mode))}",
                    algo: :aes,
                    variant: String.to_atom("aes_#{size}"),
                    mode: mode,
                    cipher: String.to_atom("aes_#{size}_#{mode}"),
                    keysize: div(size, 8)
                  }
                end)

  @camellia_vectors (for size <- [128, 192, 256], mode <- [:cbc, :gcm, :xts] do
                       %{
                         name: "Camellia-#{size}-#{String.upcase(to_string(mode))}",
                         algo: :camelia,
                         variant: String.to_atom("camelia_#{size}"),
                         mode: mode,
                         cipher: String.to_atom("camellia_#{size}_#{mode}"),
                         keysize: div(size, 8)
                       }
                     end)

  @chacha_vectors [
    %{
      name: "ChaCha20-Poly1305",
      algo: :chacha20,
      variant: :chacha20,
      mode: :gcm,
      cipher: :chacha20_poly1305,
      keysize: 32
    }
  ]

  @all_vectors @aes_vectors ++ @camellia_vectors ++ @chacha_vectors

  # Generate test artifacts for all available cipher algorithms
  for vector <- @all_vectors do
    @vector vector
    test "generate symkey_cipher test artifacts for #{@vector.name}", %{ap_java_crypto_pid: _pid} do
      generate_symkey_cipher(@vector)
    end
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

  defp generate_symkey_cipher(vector) do
    plaintext = "Secret test message for #{vector.name}"
    key = :crypto.strong_rand_bytes(vector.keysize)

    # Try to create cipher context - some ciphers may not be supported
    ctx_res = CipherContextBuilder.cipher_context(vector.cipher)

    case ctx_res do
      {:error, reason} ->
        IO.puts("Skipping unsupported cipher: #{vector.cipher} - #{inspect(reason)}")
        :skip

      ctx ->
        ctx = ExCcrypto.ContextConfig.set(ctx, :session_key, key)

        {:ok, result} =
          Cipher.cipher_init(ctx, %{})
          |> Cipher.cipher_update(plaintext)
          |> Cipher.cipher_final()

        %{cipher: cipher_bin, cipher_context: envp} = result

        # Get IV and tag based on cipher type
        iv = get_iv(envp, vector)
        tag = get_tag(envp, vector)

        symkey = %Symkey{
          version: :v1_0,
          algo: vector.algo,
          variant: vector.variant,
          raw_key: key
        }

        symkey_cipher = %SymkeyCipher{
          version: :v1_0,
          mode: vector.mode,
          symkey: symkey,
          iv: iv,
          tag: tag,
          aad: nil,
          cipher: cipher_bin
        }

        {:ok, encoded} = StrapCiphagile.encode(symkey_cipher)

        format_name =
          String.downcase("symkey_cipher_#{vector.name}")
          |> String.replace("-", "_")
          |> String.replace(" ", "_")

        save_artifact(format_name, %{plaintext: plaintext, key: key, iv: iv, tag: tag}, encoded)
    end
  end

  # Get IV from cipher context - handle different cipher types
  defp get_iv(envp, _vector) do
    session_data = Map.get(envp, :session_data, %{}) || %{}
    Map.get(session_data, :iv, nil) || ContextConfig.get(envp, :iv, nil)
  end

  # Get tag from cipher context - only relevant for AEAD ciphers (GCM, ChaCha20-Poly1305)
  defp get_tag(envp, vector) do
    if vector.mode == :gcm or vector.algo == :chacha20 do
      session_data = Map.get(envp, :session_data, %{}) || %{}
      Map.get(session_data, :tag, nil) || ContextConfig.get(envp, :tag, nil)
    else
      nil
    end
  end
end
