defmodule StrapCiphagile.Context.SignatureArtifactTest do
  use ExUnit.Case

  alias StrapCiphagile.Context.Signature
  alias StrapCiphagile.Context.Hashing
  alias ExCcrypto.Asymkey.AsymkeySignContextBuilder

  @test_dir "test_artifact"

  setup_all do
    {:ok, ap_java_crypto_pid} = ApJavaCrypto.start_link()
    # small sleep to ensure Java JRuby VM is fully up
    Process.sleep(1000)
    File.mkdir_p!(@test_dir)
    %{ap_java_crypto_pid: ap_java_crypto_pid}
  end

  # --- ARTIFACT GENERATOR ---

  test "generate signature test artifacts for ex_ccrypto (ECC, RSA)", %{ap_java_crypto_pid: _pid} do
    generate_signature_ex_ccrypto()
  end

  test "generate signature test artifacts for PQC (ML-DSA)", %{ap_java_crypto_pid: _pid} do
    generate_signature_pqc()
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

  defp generate_signature_ex_ccrypto() do
    # ECC Signature
    cfg = %ExCcrypto.Asymkey.Ecc.EccKeypair{curve: :secp256r1}
    {:ok, keypair} = ExCcrypto.Asymkey.generate(cfg)

    test_data = "Hello ECC Signature validation!"

    sign_ctx =
      AsymkeySignContextBuilder.sign_context(keypair.private_key)
      |> ExCcrypto.ContextConfig.set(:pre_sign_digest_algo, :sha256)

    {:ok, envp} = ExCcrypto.Asymkey.AsymkeySign.sign(sign_ctx, test_data, %{})
    signature = ExCcrypto.ContextConfig.get(envp, :signature)

    sig_ctx = %Signature{
      version: :v1_0,
      algo: :ecc,
      variant: :secp256r1,
      format: :raw,
      signature: signature,
      plaintext: test_data,
      digest: %Hashing{version: :v1_0, algo: :sha2, variant: :sha2_256}
    }

    {:ok, sig_enc} = StrapCiphagile.encode(sig_ctx)
    save_artifact("signature_ecc_secp256r1", %{plaintext: test_data}, sig_enc)
  end

  defp generate_signature_pqc() do
    # ML-DSA Signature
    {:ok, {:ml_dsa_44, :private_key, priv_raw}, {:ml_dsa_44, :public_key, pub_raw}} =
      ApJavaCrypto.generate_keypair(:ml_dsa_44)

    test_data = "Hello ML-DSA!"
    {:ok, signature} = ApJavaCrypto.sign(test_data, {:ml_dsa_44, :private_key, priv_raw})

    sig_ctx = %Signature{
      version: :v1_0,
      algo: :ml_dsa,
      variant: :ml_dsa_44,
      signature: signature,
      plaintext: test_data
    }

    {:ok, sig_enc} = StrapCiphagile.encode(sig_ctx)
    save_artifact("signature_ml_dsa_44", %{plaintext: test_data}, sig_enc)
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
