defmodule StrapCiphagile.Context.AsymkeyArtifactGeneratorTest do
  use ExUnit.Case
  @moduletag timeout: :infinity
  alias StrapCiphagile.Context.PublicKey
  alias StrapCiphagile.Context.PrivateKey
  alias StrapCiphagile.EncoderProtocol

  @test_dir "test_artifact"

  setup_all do
    {:ok, ap_java_crypto_pid} = ApJavaCrypto.start_link()
    # small sleep to ensure Java JRuby VM is fully up
    Process.sleep(2000)
    File.mkdir_p!(@test_dir)
    %{ap_java_crypto_pid: ap_java_crypto_pid}
  end

  # --- ARTIFACT GENERATOR ---

  test "generate asymkey test artifacts for ex_ccrypto (ECC, RSA)", %{ap_java_crypto_pid: _pid} do
    generate_asymkey_and_signature_ex_ccrypto()
  end

  test "generate asymkey test artifacts for PQC (ML-DSA, ML-KEM, KAZ-SIGN)", %{
    ap_java_crypto_pid: _pid
  } do
    generate_asymkey_and_signature_pqc()
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

  defp generate_asymkey_and_signature_ex_ccrypto() do
    # ECC
    cfg = %ExCcrypto.Asymkey.Ecc.EccKeypair{curve: :secp256r1}
    {:ok, keypair} = ExCcrypto.Asymkey.generate(cfg)
    {:ok, pub_der} = ExCcrypto.Asymkey.KeyEncoding.encode(keypair.public_key, :der)
    {:ok, priv_der} = ExCcrypto.Asymkey.KeyEncoding.encode(keypair.private_key, :der)

    pub_raw = if is_binary(pub_der), do: pub_der, else: pub_der.value
    priv_raw = if is_binary(priv_der), do: priv_der, else: priv_der.value

    pubkey = %PublicKey{version: :v1_0, algo: :ecc, variant: :secp256r1, key_value: pub_raw}

    privkey = %PrivateKey{
      version: :v1_0,
      algo: :ecc,
      variant: :secp256r1,
      enc_key_value: priv_raw
    }

    {:ok, pub_enc} = StrapCiphagile.encode(pubkey)
    {:ok, priv_enc} = StrapCiphagile.encode(privkey)

    save_artifact("public_key_ecc_secp256r1", %{key: pub_raw}, pub_enc)
    save_artifact("private_key_ecc_secp256r1", %{key: priv_raw}, priv_enc)

    # RSA
    cfg_rsa = %ExCcrypto.Asymkey.RSA.RSAKeypair{keysize: 2048}
    {:ok, keypair_rsa} = ExCcrypto.Asymkey.generate(cfg_rsa)
    {:ok, pub_der_rsa} = ExCcrypto.Asymkey.KeyEncoding.encode(keypair_rsa.public_key, :der)
    {:ok, priv_der_rsa} = ExCcrypto.Asymkey.KeyEncoding.encode(keypair_rsa.private_key, :der)

    pub_raw_rsa = if is_binary(pub_der_rsa), do: pub_der_rsa, else: pub_der_rsa.value
    priv_raw_rsa = if is_binary(priv_der_rsa), do: priv_der_rsa, else: priv_der_rsa.value

    pubkey_rsa = %PublicKey{
      version: :v1_0,
      algo: :rsa,
      variant: :rsa_2048,
      key_value: pub_raw_rsa
    }

    privkey_rsa = %PrivateKey{
      version: :v1_0,
      algo: :rsa,
      variant: :rsa_2048,
      enc_key_value: priv_raw_rsa
    }

    {:ok, pub_enc_rsa} = StrapCiphagile.encode(pubkey_rsa)
    {:ok, priv_enc_rsa} = StrapCiphagile.encode(privkey_rsa)

    save_artifact("public_key_rsa_2048", %{key: pub_raw_rsa}, pub_enc_rsa)
    save_artifact("private_key_rsa_2048", %{key: priv_raw_rsa}, priv_enc_rsa)
  end

  defp generate_asymkey_and_signature_pqc() do
    # ML-DSA
    {:ok, {:ml_dsa_44, :private_key, priv_raw}, {:ml_dsa_44, :public_key, pub_raw}} =
      ApJavaCrypto.generate_keypair(:ml_dsa_44)

    pubkey = %PublicKey{version: :v1_0, algo: :ml_dsa, variant: :ml_dsa_44, key_value: pub_raw}

    privkey = %PrivateKey{
      version: :v1_0,
      algo: :ml_dsa,
      variant: :ml_dsa_44,
      enc_key_value: priv_raw
    }

    {:ok, pub_enc} = StrapCiphagile.encode(pubkey)
    {:ok, priv_enc} = StrapCiphagile.encode(privkey)
    save_artifact("public_key_ml_dsa_44", %{key: pub_raw}, pub_enc)
    save_artifact("private_key_ml_dsa_44", %{key: priv_raw}, priv_enc)

    # ML-KEM
    {:ok, {:ml_kem_512, :private_key, kem_priv_raw}, {:ml_kem_512, :public_key, kem_pub_raw}} =
      ApJavaCrypto.generate_keypair(:ml_kem_512)

    kem_pubkey = %PublicKey{
      version: :v1_0,
      algo: :ml_kem,
      variant: :ml_kem_512,
      key_value: kem_pub_raw
    }

    kem_privkey = %PrivateKey{
      version: :v1_0,
      algo: :ml_kem,
      variant: :ml_kem_512,
      enc_key_value: kem_priv_raw
    }

    {:ok, kem_pub_enc} = StrapCiphagile.encode(kem_pubkey)
    {:ok, kem_priv_enc} = StrapCiphagile.encode(kem_privkey)
    save_artifact("public_key_ml_kem_512", %{key: kem_pub_raw}, kem_pub_enc)
    save_artifact("private_key_ml_kem_512", %{key: kem_priv_raw}, kem_priv_enc)

    # KAZ-SIGN
    {:ok, {:kaz_sign_128, :private_key, kaz_priv_raw}, {:kaz_sign_128, :public_key, kaz_pub_raw}} =
      ApJavaCrypto.generate_keypair(:kaz_sign_128)

    kaz_pubkey = %PublicKey{
      version: :v1_0,
      algo: :kaz_sign,
      variant: :kaz_sign_128_v1_6_4,
      key_value: kaz_pub_raw
    }

    kaz_privkey = %PrivateKey{
      version: :v1_0,
      algo: :kaz_sign,
      variant: :kaz_sign_128_v1_6_4,
      enc_key_value: kaz_priv_raw
    }

    {:ok, kaz_pub_enc} = StrapCiphagile.encode(kaz_pubkey)
    {:ok, kaz_priv_enc} = StrapCiphagile.encode(kaz_privkey)
    save_artifact("public_key_kaz_sign_128", %{key: kaz_pub_raw}, kaz_pub_enc)
    save_artifact("private_key_kaz_sign_128", %{key: kaz_priv_raw}, kaz_priv_enc)
  end
end
