defmodule StrapCiphagile.Context.SignatureTest do
  use ExUnit.Case

  alias StrapCiphagile.Context.Signature
  alias StrapCiphagile.Context.Hashing
  alias StrapCiphagile.EncoderProtocol
  alias StrapCiphagile.DecoderProtocol
  alias ExCcrypto.Asymkey.Ecc.EccPublicKey
  alias ExCcrypto.Asymkey.Ecc.EccVerifyContext
  alias ExCcrypto.Asymkey.AsymkeySignContextBuilder
  alias ExCcrypto.Asymkey.RSA.RSAPublicKey
  alias ExCcrypto.Asymkey.RSA.RSAVerifyContext

  @test_dir "test_artifact"

  setup_all do
    {:ok, ap_java_crypto_pid} = ApJavaCrypto.start_link()
    # small sleep to ensure Java JRuby VM is fully up
    Process.sleep(1000)
    File.mkdir_p!(@test_dir)
    %{ap_java_crypto_pid: ap_java_crypto_pid}
  end

  describe "encode/decode Signature context" do
    for curve <- [
          :secp112r1,
          :secp112r2,
          :secp128r1,
          :secp128r2,
          :secp160k1,
          :secp160r1,
          :secp160r2,
          :secp192k1,
          :secp192r1,
          :secp224k1,
          :secp224r1,
          :secp256k1,
          :secp256r1,
          :secp384r1,
          :secp521r1,
          :prime192v1,
          :prime192v2,
          :prime192v3,
          :prime239v1,
          :prime239v2,
          :prime239v3,
          :prime256v1,
          :sect113r1,
          :sect113r2,
          :sect131r1,
          :sect131r2,
          :sect163k1,
          :sect163r1,
          :sect163r2,
          :sect193r1,
          :sect193r2,
          :sect233k1,
          :sect233r1,
          :sect239k1,
          :sect283k1,
          :sect283r1,
          :sect409k1,
          :sect409r1,
          :sect571k1,
          :sect571r1,
          :brainpoolp160r1,
          :brainpoolp160t1,
          :brainpoolp192r1,
          :brainpoolp192t1,
          :brainpoolp224r1,
          :brainpoolp224t1,
          :brainpoolp256r1,
          :brainpoolp256t1,
          :brainpoolp320r1,
          :brainpoolp320t1,
          :brainpoolp384r1,
          :brainpoolp384t1,
          :brainpoolp512r1,
          :brainpoolp512t1
        ] do
      test "ECC #{curve} via ex_ccrypto" do
        curve_atom = unquote(curve)
        cfg = %ExCcrypto.Asymkey.Ecc.EccKeypair{curve: curve_atom}

        case ExCcrypto.Asymkey.generate(cfg) do
          {:ok, keypair} ->
            test_data = "Hello ECC #{curve_atom} Signature validation!"

            sign_ctx = AsymkeySignContextBuilder.sign_context(keypair.private_key)

            case ExCcrypto.Asymkey.AsymkeySign.sign(sign_ctx, test_data, %{}) do
              {:ok, envp} ->
                raw_signature = ExCcrypto.ContextConfig.get(envp, :signature)

                # Create Signature struct
                sig_ctx = %Signature{
                  version: :v1_0,
                  algo: :ecc,
                  variant: curve_atom,
                  format: :raw,
                  signature: raw_signature,
                  plaintext: test_data,
                  digest: %Hashing{version: :v1_0, algo: :sha2, variant: :sha2_256}
                }

                assert {:ok, encoded} = EncoderProtocol.encode(sig_ctx)
                assert {:ok, decoded} = DecoderProtocol.decode(%Signature{}, encoded)

                assert decoded.algo == :ecc
                assert decoded.variant == curve_atom
                assert decoded.format == :raw
                assert decoded.signature == raw_signature
                assert decoded.plaintext == test_data
                assert decoded.digest.algo == :sha2
                assert decoded.digest.variant == :sha2_256

                # Full system integration decode wrapper
                assert {:ok, sig_wrap_encoded} = StrapCiphagile.encode(sig_ctx)
                assert {:ok, decoded_wrap} = StrapCiphagile.decode(sig_wrap_encoded)

                assert decoded_wrap.signature == raw_signature
                assert decoded_wrap.plaintext == test_data

                # Encode public key for verification recovery scenario
                {:ok, pub_raw} = ExCcrypto.Asymkey.KeyEncoding.encode(keypair.public_key, :der)

                # Recover native public key from raw bytes
                {:ok, native_pub} = X509.PublicKey.from_der(pub_raw)

                recovered_pub_key = %EccPublicKey{format: :native, value: native_pub}

                # Verify using decoded Signature struct attributes
                {:ok, verRes} =
                  ExCcrypto.Asymkey.AsymkeyVerify.verify_init(envp, %{
                    verification_key: recovered_pub_key
                  })
                  |> ExCcrypto.Asymkey.AsymkeyVerify.verify_update(decoded_wrap.plaintext)
                  |> ExCcrypto.Asymkey.AsymkeyVerify.verify_final(decoded_wrap.signature)

                assert verRes.verification_result == true

              {:error, _} ->
                :ok
            end

          {:error, _} ->
            :ok
        end
      end
    end

    for {variant, keysize} <- [
          rsa_1024: 1024,
          rsa_2048: 2048,
          rsa_3072: 3072,
          rsa_4096: 4096,
          rsa_8192: 8192
        ] do
      test "RSA-#{keysize} via ex_ccrypto" do
        variant = unquote(variant)
        keysize = unquote(keysize)
        cfg = %ExCcrypto.Asymkey.RSA.RSAKeypair{keysize: keysize}
        {:ok, keypair} = ExCcrypto.Asymkey.generate(cfg)

        test_data = "Hello RSA-#{keysize} Signature validation!"

        sign_ctx =
          AsymkeySignContextBuilder.sign_context(keypair.private_key)
          |> ExCcrypto.ContextConfig.set(:pre_sign_digest_algo, :sha256)

        {:ok, envp} = ExCcrypto.Asymkey.AsymkeySign.sign(sign_ctx, test_data, %{})
        raw_signature = ExCcrypto.ContextConfig.get(envp, :signature)

        # Create Signature struct
        sig_ctx = %Signature{
          version: :v1_0,
          algo: :rsa,
          variant: variant,
          format: :raw,
          signature: raw_signature,
          plaintext: test_data,
          digest: %StrapCiphagile.Context.Hashing{version: :v1_0, algo: :sha2, variant: :sha2_256}
        }

        assert {:ok, encoded} = EncoderProtocol.encode(sig_ctx)
        assert {:ok, decoded} = DecoderProtocol.decode(%Signature{}, encoded)

        assert decoded.algo == :rsa
        assert decoded.variant == variant
        assert decoded.format == :raw
        assert decoded.signature == raw_signature
        assert decoded.plaintext == test_data
        assert decoded.digest.algo == :sha2
        assert decoded.digest.variant == :sha2_256

        # Full system integration decode wrapper
        assert {:ok, sig_wrap_encoded} = StrapCiphagile.encode(sig_ctx)
        assert {:ok, decoded_wrap} = StrapCiphagile.decode(sig_wrap_encoded)

        assert decoded_wrap.signature == raw_signature
        assert decoded_wrap.plaintext == test_data

        # Encode public key for verification recovery scenario
        {:ok, pub_raw} = ExCcrypto.Asymkey.KeyEncoding.encode(keypair.public_key, :der)

        {:ok, native_pub} = X509.PublicKey.from_der(pub_raw)

        recovered_pub_key = %ExCcrypto.Asymkey.RSA.RSAPublicKey{
          format: :native,
          value: native_pub
        }

        # Create verify context and verify Using Decoded Signature struct
        {:ok, verRes} =
          ExCcrypto.Asymkey.AsymkeyVerify.verify_init(envp, %{verification_key: recovered_pub_key})
          |> ExCcrypto.Asymkey.AsymkeyVerify.verify_update(decoded_wrap.plaintext)
          |> ExCcrypto.Asymkey.AsymkeyVerify.verify_final(decoded_wrap.signature)

        assert verRes.verification_result == true
      end
    end

    test "ML-DSA via ApJavaCrypto" do
      case ApJavaCrypto.generate_keypair(:ml_dsa_87) do
        {:ok, {:ml_dsa_87, :private_key, priv_raw}, {:ml_dsa_87, :public_key, pub_raw}} ->
          test_data = "Hello ML-DSA Signature validation!"

          # ApJavaCrypto args: {:sign, data, {algo, :private_key, privkey}, opts}
          {:ok, signature} = ApJavaCrypto.sign(test_data, {:ml_dsa_87, :private_key, priv_raw})

          # Create Signature struct
          sig_ctx = %Signature{
            version: :v1_0,
            algo: :ml_dsa,
            variant: :ml_dsa_87,
            signature: signature,
            plaintext: test_data
          }

          assert {:ok, encoded} = EncoderProtocol.encode(sig_ctx)
          assert {:ok, decoded} = DecoderProtocol.decode(%Signature{}, encoded)

          assert decoded.algo == :ml_dsa
          assert decoded.variant == :ml_dsa_87
          assert decoded.signature == signature
          assert decoded.plaintext == test_data

          # Full system integration decode wrapper
          assert {:ok, sig_wrap_encoded} = StrapCiphagile.encode(sig_ctx)
          assert {:ok, decoded_wrap} = StrapCiphagile.decode(sig_wrap_encoded)

          assert decoded_wrap.signature == signature
          assert decoded_wrap.plaintext == test_data

          # Verify with original public key via ApJavaCrypto using decoded struct attrs
          {:ok, is_valid} =
            ApJavaCrypto.verify(
              decoded_wrap.plaintext,
              decoded_wrap.signature,
              {:ml_dsa_87, :public_key, pub_raw}
            )

          assert is_valid == true

        {:error, _} ->
          :ok
      end
    end

    test "KAZ-SIGN via ApJavaCrypto" do
      case ApJavaCrypto.generate_keypair(:kaz_sign_128) do
        {:ok, {:kaz_sign_128, :private_key, priv_raw}, {:kaz_sign_128, :public_key, pub_raw}} ->
          test_data = "Hello KAZ-SIGN Signature validation via ApJavaCrypto!"

          {:ok, signature} = ApJavaCrypto.sign(test_data, {:kaz_sign_128, :private_key, priv_raw})

          # Create Signature struct
          sig_ctx = %Signature{
            version: :v1_0,
            algo: :kaz_sign,
            variant: :kaz_sign_128_v1_6_4,
            signature: signature,
            plaintext: test_data
          }

          assert {:ok, encoded} = EncoderProtocol.encode(sig_ctx)
          assert {:ok, decoded} = DecoderProtocol.decode(%Signature{}, encoded)

          assert decoded.algo == :kaz_sign
          assert decoded.variant == :kaz_sign_128_v1_6_4
          assert decoded.signature == signature
          assert decoded.plaintext == test_data

          # Full system integration decode wrapper
          assert {:ok, sig_wrap_encoded} = StrapCiphagile.encode(sig_ctx)
          assert {:ok, decoded_wrap} = StrapCiphagile.decode(sig_wrap_encoded)

          assert decoded_wrap.signature == signature
          assert decoded_wrap.plaintext == test_data

          # Verify using decoded struct
          {:ok, is_valid} =
            ApJavaCrypto.verify(
              decoded_wrap.plaintext,
              decoded_wrap.signature,
              {:kaz_sign_128, :public_key, pub_raw}
            )

          assert is_valid == true

        {:error, _} ->
          :ok
      end
    end

    test "decode with random data at the back" do
      # Create a simple Signature struct
      sig_ctx = %Signature{
        version: :v1_0,
        algo: :rsa,
        variant: :rsa_2048,
        format: :raw,
        signature: "sig_bytes",
        plaintext: "test message"
      }

      {:ok, encoded} = EncoderProtocol.encode(sig_ctx)
      random_garbage = :crypto.strong_rand_bytes(10)
      full_binary = encoded <> random_garbage

      # DecoderProtocol returns {:ok, {struct, rest}} if rest not empty
      assert {:ok, {decoded_sig, rest}} = DecoderProtocol.decode(%Signature{}, full_binary)
      assert decoded_sig == sig_ctx
      assert rest == random_garbage
    end
  end
end
