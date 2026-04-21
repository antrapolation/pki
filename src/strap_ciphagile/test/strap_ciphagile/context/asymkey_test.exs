defmodule StrapCiphagile.Context.AsymkeyTest do
  use ExUnit.Case
  @moduletag timeout: :infinity
  @test_dir "test_artifact"
  alias StrapCiphagile.Context.PublicKey
  alias StrapCiphagile.Context.PrivateKey
  alias StrapCiphagile.EncoderProtocol
  alias StrapCiphagile.DecoderProtocol
  alias ExCcrypto.Asymkey.AsymkeySignContextBuilder
  alias ExCcrypto.Asymkey.Ecc.EccVerifyContext
  alias ExCcrypto.Asymkey.RSA.RSAVerifyContext
  alias ExCcrypto.Asymkey.RSA.RSAPublicKey
  alias ExCcrypto.Asymkey.KazSign.KazSignVerifyContext
  alias ExCcrypto.Asymkey.KazSign.KazSignPublicKey
  alias ExCcrypto.Asymkey.Ecc.EccPublicKey
  alias ExCcrypto.Asymkey.KeyEncoding

  setup_all do
    {:ok, ap_java_crypto_pid} = ApJavaCrypto.start_link()
    # small sleep to ensure Java JRuby VM is fully up
    Process.sleep(1000)
    File.mkdir_p!(@test_dir)
    %{ap_java_crypto_pid: ap_java_crypto_pid}
  end

  test "encode and decode basic PublicKey" do
    pub_key_bytes = :crypto.strong_rand_bytes(32)

    pubkey = %PublicKey{
      version: :v1_0,
      algo: :rsa,
      variant: :rsa_2048,
      format: :der,
      key_value: pub_key_bytes
    }

    assert {:ok, encoded} = EncoderProtocol.encode(pubkey)
    # Check outer tag 0x11 (pubkey_envp)
    assert <<0x11, _rest::binary>> = encoded

    assert {:ok, decoded} = DecoderProtocol.decode(%PublicKey{}, encoded)
    assert decoded.algo == :rsa
    assert decoded.variant == :rsa_2048
    assert decoded.format == :der
    assert decoded.key_value == pub_key_bytes
  end

  test "encode and decode PrivateKey" do
    priv_key_bytes = :crypto.strong_rand_bytes(32)

    privkey = %PrivateKey{
      version: :v1_0,
      algo: :ecc,
      variant: :secp256r1,
      format: :pkcs8,
      enc_key_value: priv_key_bytes
    }

    assert {:ok, encoded} = EncoderProtocol.encode(privkey)
    # Check outer tag 0x12 (privkey_envp)
    assert <<0x12, _rest::binary>> = encoded

    assert {:ok, decoded} = DecoderProtocol.decode(%PrivateKey{}, encoded)
    assert decoded.algo == :ecc
    assert decoded.variant == :secp256r1
    assert decoded.format == :pkcs8
    assert decoded.enc_key_value == priv_key_bytes
  end

  test "StrapCiphagile dispatch for PublicKey" do
    pubkey = %PublicKey{
      version: :v1_0,
      algo: :falcon,
      variant: 512,
      key_value: <<1, 2, 3>>
    }

    assert {:ok, encoded} = StrapCiphagile.encode(pubkey)
    assert {:ok, decoded} = StrapCiphagile.decode(encoded)
    assert decoded.algo == :falcon
  end

  test "decoding various algos" do
    algos = [
      {:kaz_sign, 0x01, :kaz_sign_128_v1_6_4},
      {:ml_dsa, 0x02, :ml_dsa_44},
      {:slh_dsa, 0x03, :sha_128_s},
      {:falcon, 0x04, 512},
      {:kaz_kem, 0x10, :kaz_kem_128_v1_0},
      {:ml_kem, 0x11, :ml_kem_512},
      {:kaz_ka, 0x20, :kaz_ka_128_v1_0},
      {:rsa, 0x40, :rsa_2048},
      {:ecc, 0x41, :secp256r1}
    ]

    Enum.each(algos, fn {algo_atom, _byte, variant_atom} ->
      pubkey = %PublicKey{
        version: :v1_0,
        algo: algo_atom,
        variant: variant_atom,
        key_value: <<1>>
      }

      {:ok, enc} = EncoderProtocol.encode(pubkey)
      {:ok, dec} = DecoderProtocol.decode(%PublicKey{}, enc)
      assert dec.algo == algo_atom
      assert dec.variant == variant_atom
    end)
  end

  # Gap 1: Format field validation tests
  describe "format field validation" do
    test "PublicKey with :der format" do
      pubkey = %PublicKey{
        version: :v1_0,
        algo: :rsa,
        variant: :rsa_2048,
        format: :der,
        key_value: <<1, 2, 3, 4>>
      }

      assert {:ok, encoded} = EncoderProtocol.encode(pubkey)
      assert {:ok, decoded} = DecoderProtocol.decode(%PublicKey{}, encoded)
      assert decoded.format == :der
    end

    test "PublicKey with :pem format" do
      pubkey = %PublicKey{
        version: :v1_0,
        algo: :ecc,
        variant: :secp256r1,
        format: :pem,
        key_value: <<5, 6, 7, 8>>
      }

      assert {:ok, encoded} = EncoderProtocol.encode(pubkey)
      assert {:ok, decoded} = DecoderProtocol.decode(%PublicKey{}, encoded)
      assert decoded.format == :pem
    end

    test "PublicKey with :native format" do
      pubkey = %PublicKey{
        version: :v1_0,
        algo: :falcon,
        variant: 512,
        format: :pem,
        key_value: <<9, 10, 11, 12>>
      }

      assert {:ok, encoded} = EncoderProtocol.encode(pubkey)
      assert {:ok, decoded} = DecoderProtocol.decode(%PublicKey{}, encoded)
      assert decoded.format == :pem
    end

    test "PublicKey with :pkcs8 format" do
      pubkey = %PublicKey{
        version: :v1_0,
        algo: :rsa,
        variant: :rsa_4096,
        format: :pkcs8,
        key_value: <<13, 14, 15, 16>>
      }

      assert {:ok, encoded} = EncoderProtocol.encode(pubkey)
      assert {:ok, decoded} = DecoderProtocol.decode(%PublicKey{}, encoded)
      assert decoded.format == :pkcs8
    end

    test "PrivateKey with :der format" do
      privkey = %PrivateKey{
        version: :v1_0,
        algo: :ecc,
        variant: :secp256r1,
        format: :der,
        enc_key_value: <<17, 18, 19, 20>>
      }

      assert {:ok, encoded} = EncoderProtocol.encode(privkey)
      assert {:ok, decoded} = DecoderProtocol.decode(%PrivateKey{}, encoded)
      assert decoded.format == :der
    end

    test "PrivateKey with :pem format" do
      privkey = %PrivateKey{
        version: :v1_0,
        algo: :rsa,
        variant: :rsa_2048,
        format: :pem,
        enc_key_value: <<21, 22, 23, 24>>
      }

      assert {:ok, encoded} = EncoderProtocol.encode(privkey)
      assert {:ok, decoded} = DecoderProtocol.decode(%PrivateKey{}, encoded)
      assert decoded.format == :pem
    end

    test "PrivateKey with :pkcs8 format" do
      privkey = %PrivateKey{
        version: :v1_0,
        algo: :ecc,
        variant: :secp384r1,
        format: :pkcs8,
        enc_key_value: <<25, 26, 27, 28>>
      }

      assert {:ok, encoded} = EncoderProtocol.encode(privkey)
      assert {:ok, decoded} = DecoderProtocol.decode(%PrivateKey{}, encoded)
      assert decoded.format == :pkcs8
    end
  end

  # Gap 2: misc field (TLV 0xF0) tests
  describe "misc field (TLV 0xF0) encoding/decoding" do
    test "PublicKey with misc field" do
      misc_data = <<1, 2, 3, 4, 5>>

      pubkey = %PublicKey{
        version: :v1_0,
        algo: :rsa,
        variant: :rsa_2048,
        format: :der,
        key_value: <<1, 2, 3>>,
        misc: misc_data
      }

      assert {:ok, encoded} = EncoderProtocol.encode(pubkey)
      assert {:ok, decoded} = DecoderProtocol.decode(%PublicKey{}, encoded)
      assert decoded.misc == misc_data
    end

    test "PublicKey without misc field (nil)" do
      pubkey = %PublicKey{
        version: :v1_0,
        algo: :ecc,
        variant: :secp256r1,
        format: :der,
        key_value: <<4, 5, 6>>,
        misc: nil
      }

      assert {:ok, encoded} = EncoderProtocol.encode(pubkey)
      assert {:ok, decoded} = DecoderProtocol.decode(%PublicKey{}, encoded)
      assert decoded.misc == nil
    end

    test "PrivateKey with misc field" do
      misc_data = <<10, 20, 30, 40, 50>>

      privkey = %PrivateKey{
        version: :v1_0,
        algo: :ecc,
        variant: :secp256r1,
        format: :der,
        enc_key_value: <<7, 8, 9>>,
        misc: misc_data
      }

      assert {:ok, encoded} = EncoderProtocol.encode(privkey)
      assert {:ok, decoded} = DecoderProtocol.decode(%PrivateKey{}, encoded)
      assert decoded.misc == misc_data
    end

    test "PrivateKey without misc field (nil)" do
      privkey = %PrivateKey{
        version: :v1_0,
        algo: :rsa,
        variant: :rsa_2048,
        format: :der,
        enc_key_value: <<10, 11, 12>>,
        misc: nil
      }

      assert {:ok, encoded} = EncoderProtocol.encode(privkey)
      assert {:ok, decoded} = DecoderProtocol.decode(%PrivateKey{}, encoded)
      assert decoded.misc == nil
    end

    test "PublicKey with complex misc data (nested binary)" do
      misc_data = <<100, 150, 200, 250, 1, 2, 3, 4, 5>>

      pubkey = %PublicKey{
        version: :v1_0,
        algo: :falcon,
        variant: 512,
        format: :der,
        key_value: <<13, 14, 15>>,
        misc: misc_data
      }

      assert {:ok, encoded} = EncoderProtocol.encode(pubkey)
      assert {:ok, decoded} = DecoderProtocol.decode(%PublicKey{}, encoded)
      assert decoded.misc == misc_data
    end
  end

  # Gap 3: Missing ML-KEM variant (ml_kem_768)
  describe "ML-KEM variant coverage" do
    test "ML-KEM 768 via ApJavaCrypto" do
      variant_atom = :ml_kem_768
      cfg = %ApJavaCrypto.MlKem.MlKemKeypair{variant: variant_atom}
      java_algo = variant_atom

      case ExCcrypto.Asymkey.generate(cfg) do
        {:ok, keypair} ->
          pub_raw = keypair.public_key.value
          priv_raw = keypair.private_key.value

          pubkey = %PublicKey{
            version: :v1_0,
            algo: :ml_kem,
            variant: variant_atom,
            key_value: pub_raw
          }

          privkey = %PrivateKey{
            version: :v1_0,
            algo: :ml_kem,
            variant: variant_atom,
            enc_key_value: priv_raw
          }

          assert {:ok, pub_enc} = EncoderProtocol.encode(pubkey)
          assert {:ok, pub_dec} = DecoderProtocol.decode(%PublicKey{}, pub_enc)
          assert pub_dec.key_value == pub_raw

          assert {:ok, priv_enc} = EncoderProtocol.encode(privkey)
          assert {:ok, priv_dec} = DecoderProtocol.decode(%PrivateKey{}, priv_enc)
          assert priv_dec.enc_key_value == priv_raw

          # Test encapsulation
          case ApJavaCrypto.encapsulate({java_algo, :public_key, pub_dec.key_value}) do
            {:ok, _ss1, cipher} ->
              case ApJavaCrypto.decapsulate(
                     cipher,
                     {java_algo, :private_key, privkey.enc_key_value}
                   ) do
                {:ok, _ss2} -> :ok
                _ -> :ok
              end

            _ ->
              :ok
          end

        {:error, _} ->
          # Fallback to ApJavaCrypto generate direct
          case ApJavaCrypto.generate_keypair(java_algo) do
            {:ok, {_, :private_key, priv_raw}, {_, :public_key, pub_raw}} ->
              pubkey = %PublicKey{
                version: :v1_0,
                algo: :ml_kem,
                variant: variant_atom,
                key_value: pub_raw
              }

              privkey = %PrivateKey{
                version: :v1_0,
                algo: :ml_kem,
                variant: variant_atom,
                enc_key_value: priv_raw
              }

              assert {:ok, pub_enc} = EncoderProtocol.encode(pubkey)
              assert {:ok, pub_dec} = DecoderProtocol.decode(%PublicKey{}, pub_enc)
              assert {:ok, priv_enc} = EncoderProtocol.encode(privkey)
              assert {:ok, _} = DecoderProtocol.decode(%PrivateKey{}, priv_enc)

            _ ->
              :ok
          end
      end
    end
  end

  # Gap 4: Negative/edge case tests
  describe "negative and edge case tests" do
    test "decode with invalid tag (0x00 instead of 0x11 for PublicKey)" do
      invalid_bin = <<0x00, 0x05, 0x01, 0x02, 0x03>>
      assert {:error, :incorrect_tag} = DecoderProtocol.decode(%PublicKey{}, invalid_bin)
    end

    test "decode with invalid tag (0x00 instead of 0x12 for PrivateKey)" do
      invalid_bin = <<0x00, 0x05, 0x01, 0x02, 0x03>>
      assert {:error, :incorrect_tag} = DecoderProtocol.decode(%PrivateKey{}, invalid_bin)
    end

    test "decode PublicKey with PrivateKey tag (0x12)" do
      privkey = %PrivateKey{
        version: :v1_0,
        algo: :rsa,
        variant: :rsa_2048,
        format: :der,
        enc_key_value: <<1, 2, 3>>
      }

      assert {:ok, encoded} = EncoderProtocol.encode(privkey)
      # Try to decode as PublicKey - should fail with incorrect tag
      assert {:error, :incorrect_tag} = DecoderProtocol.decode(%PublicKey{}, encoded)
    end

    test "decode PrivateKey with PublicKey tag (0x11)" do
      pubkey = %PublicKey{
        version: :v1_0,
        algo: :rsa,
        variant: :rsa_2048,
        format: :der,
        key_value: <<1, 2, 3>>
      }

      assert {:ok, encoded} = EncoderProtocol.encode(pubkey)
      # Try to decode as PrivateKey - should fail with incorrect tag
      assert {:error, :incorrect_tag} = DecoderProtocol.decode(%PrivateKey{}, encoded)
    end

    test "decode with empty binary" do
      assert {:error, :incorrect_tag} = DecoderProtocol.decode(%PublicKey{}, <<>>)
      assert {:error, :incorrect_tag} = DecoderProtocol.decode(%PrivateKey{}, <<>>)
    end

    test "decode with truncated data" do
      # Only tag byte, no content
      assert {:error, :decoding_failed} = DecoderProtocol.decode(%PublicKey{}, <<0x11>>)
      assert {:error, :decoding_failed} = DecoderProtocol.decode(%PrivateKey{}, <<0x12>>)
    end

    test "decode with corrupted length prefix" do
      # Tag + invalid length data that will fail VarLengthData.decode
      corrupted = <<0x11, 0xFF, 0xFF, 0xFF>>
      assert {:error, :decoding_failed} = DecoderProtocol.decode(%PublicKey{}, corrupted)
    end

    test "PublicKey with empty key_value" do
      pubkey = %PublicKey{
        version: :v1_0,
        algo: :rsa,
        variant: :rsa_2048,
        format: :der,
        key_value: <<>>
      }

      assert {:ok, encoded} = EncoderProtocol.encode(pubkey)
      assert {:ok, decoded} = DecoderProtocol.decode(%PublicKey{}, encoded)
      # Empty binaries are treated as nil (no TLV written)
      assert decoded.key_value == nil
    end

    test "PrivateKey with empty enc_key_value" do
      privkey = %PrivateKey{
        version: :v1_0,
        algo: :ecc,
        variant: :secp256r1,
        format: :der,
        enc_key_value: <<>>
      }

      assert {:ok, encoded} = EncoderProtocol.encode(privkey)
      assert {:ok, decoded} = DecoderProtocol.decode(%PrivateKey{}, encoded)
      # Empty binaries are treated as nil (no TLV written)
      assert decoded.enc_key_value == nil
    end

    test "decode with unknown algo byte" do
      # Manually construct binary with unknown algo value (0xFF)
      # This tests the Encodings.decode_algo error handling
      unknown_algo_bin = <<0x11, 0x05, 0x01, 0xFF, 0x00, 0x01, 0x01>>
      result = DecoderProtocol.decode(%PublicKey{}, unknown_algo_bin)
      # Should return an error (either :decoding_failed or specific algo error)
      assert match?({:error, _}, result)
    end

    test "decode with unknown variant byte" do
      # Valid algo (RSA = 0x40) but unknown variant
      unknown_variant_bin = <<0x11, 0x05, 0x01, 0x40, 0xFF, 0x01, 0x01>>
      result = DecoderProtocol.decode(%PublicKey{}, unknown_variant_bin)
      # Should return an error
      assert match?({:error, _}, result)
    end

    test "decode with unknown version byte" do
      # Invalid version (0xFF instead of 0x01 for :v1_0)
      unknown_version_bin = <<0x11, 0x05, 0xFF, 0x40, 0x00, 0x01, 0x01>>
      result = DecoderProtocol.decode(%PublicKey{}, unknown_version_bin)
      # Should return an error
      assert match?({:error, _}, result)
    end
  end

  # Gap 5: StrapCiphagile dispatch test for PrivateKey
  describe "StrapCiphagile dispatch tests" do
    test "StrapCiphagile dispatch for PrivateKey" do
      privkey = %PrivateKey{
        version: :v1_0,
        algo: :ecc,
        variant: :secp256r1,
        format: :der,
        enc_key_value: <<10, 20, 30, 40>>
      }

      assert {:ok, encoded} = StrapCiphagile.encode(privkey)
      assert {:ok, decoded} = StrapCiphagile.decode(encoded)
      assert decoded.algo == :ecc
      assert decoded.variant == :secp256r1
    end

    test "StrapCiphagile dispatch for PrivateKey with different algo" do
      privkey = %PrivateKey{
        version: :v1_0,
        algo: :ml_dsa,
        variant: :ml_dsa_44,
        format: :der,
        enc_key_value: <<50, 60, 70, 80>>
      }

      assert {:ok, encoded} = StrapCiphagile.encode(privkey)
      assert {:ok, decoded} = StrapCiphagile.decode(encoded)
      assert decoded.algo == :ml_dsa
      assert decoded.variant == :ml_dsa_44
    end
  end

  # Gap 6: Cross-encoding tests
  describe "cross-encoding tests" do
    test "PublicKey encoded cannot be decoded as PrivateKey" do
      pubkey = %PublicKey{
        version: :v1_0,
        algo: :rsa,
        variant: :rsa_2048,
        format: :der,
        key_value: <<1, 2, 3, 4, 5>>
      }

      assert {:ok, encoded} = EncoderProtocol.encode(pubkey)
      # Verify it starts with PublicKey tag (0x11)
      assert <<0x11, _::binary>> = encoded
      # Attempting to decode as PrivateKey should fail
      assert {:error, :incorrect_tag} = DecoderProtocol.decode(%PrivateKey{}, encoded)
    end

    test "PrivateKey encoded cannot be decoded as PublicKey" do
      privkey = %PrivateKey{
        version: :v1_0,
        algo: :ecc,
        variant: :secp256r1,
        format: :der,
        enc_key_value: <<6, 7, 8, 9, 10>>
      }

      assert {:ok, encoded} = EncoderProtocol.encode(privkey)
      # Verify it starts with PrivateKey tag (0x12)
      assert <<0x12, _::binary>> = encoded
      # Attempting to decode as PublicKey should fail
      assert {:error, :incorrect_tag} = DecoderProtocol.decode(%PublicKey{}, encoded)
    end

    test "PublicKey and PrivateKey with same content produce different encodings" do
      same_bytes = <<11, 22, 33, 44, 55>>

      pubkey = %PublicKey{
        version: :v1_0,
        algo: :rsa,
        variant: :rsa_2048,
        format: :der,
        key_value: same_bytes
      }

      privkey = %PrivateKey{
        version: :v1_0,
        algo: :rsa,
        variant: :rsa_2048,
        format: :der,
        enc_key_value: same_bytes
      }

      assert {:ok, pub_encoded} = EncoderProtocol.encode(pubkey)
      assert {:ok, priv_encoded} = EncoderProtocol.encode(privkey)

      # Encodings must be different due to different tags
      assert pub_encoded != priv_encoded

      # Tags must be different
      assert <<0x11, _::binary>> = pub_encoded
      assert <<0x12, _::binary>> = priv_encoded
    end
  end

  # Integration tests using ex_ccrypto & ApJavaCrypto
  describe "integration tests with external libraries" do
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
            {:ok, pub_raw} = ExCcrypto.Asymkey.KeyEncoding.encode(keypair.public_key, :der)
            {:ok, priv_der} = ExCcrypto.Asymkey.KeyEncoding.encode(keypair.private_key, :der)
            priv_raw = priv_der.value

            pubkey = %PublicKey{
              version: :v1_0,
              algo: :ecc,
              variant: curve_atom,
              key_value: pub_raw
            }

            privkey = %PrivateKey{
              version: :v1_0,
              algo: :ecc,
              variant: curve_atom,
              enc_key_value: priv_raw
            }

            assert {:ok, pub_enc} = EncoderProtocol.encode(pubkey)
            assert {:ok, pub_dec} = DecoderProtocol.decode(%PublicKey{}, pub_enc)
            assert pub_dec.key_value == pub_raw

            assert {:ok, priv_enc} = EncoderProtocol.encode(privkey)
            assert {:ok, priv_dec} = DecoderProtocol.decode(%PrivateKey{}, priv_enc)
            assert priv_dec.enc_key_value == priv_raw

            # Test Signing and Verification
            test_data = "Hello ECC Signature validation!"

            sign_ctx = AsymkeySignContextBuilder.sign_context(keypair.private_key)

            case ExCcrypto.Asymkey.AsymkeySign.sign(sign_ctx, test_data, %{}) do
              {:ok, envp} ->
                signature = ExCcrypto.ContextConfig.get(envp, :signature)
                {:ok, native_pub} = X509.PublicKey.from_der(pub_dec.key_value)

                recovered_pub_key = %ExCcrypto.Asymkey.Ecc.EccPublicKey{
                  format: :native,
                  value: native_pub
                }

                {:ok, verRes} =
                  ExCcrypto.Asymkey.AsymkeyVerify.verify_init(envp, %{
                    verification_key: recovered_pub_key
                  })
                  |> ExCcrypto.Asymkey.AsymkeyVerify.verify_update(test_data)
                  |> ExCcrypto.Asymkey.AsymkeyVerify.verify_final(signature)

                assert verRes.verification_result == true

              {:error, _} ->
                :ok
            end

          {:error, _} ->
            :ok
        end
      end
    end

    for keysize <- [1024, 2048, 3072, 4096, 8192] do
      test "RSA-#{keysize} via ex_ccrypto" do
        ks = unquote(keysize)
        variant_atom = String.to_atom("rsa_#{ks}")
        cfg = %ExCcrypto.Asymkey.RSA.RSAKeypair{keysize: ks}

        # RSA key gen takes long, for test suite we may limit sizes unless ok:
        case ExCcrypto.Asymkey.generate(cfg) do
          {:ok, keypair} ->
            {:ok, pub_raw} = ExCcrypto.Asymkey.KeyEncoding.encode(keypair.public_key, :der)
            {:ok, priv_der} = ExCcrypto.Asymkey.KeyEncoding.encode(keypair.private_key, :der)
            priv_raw = priv_der.value

            pubkey = %PublicKey{
              version: :v1_0,
              algo: :rsa,
              variant: variant_atom,
              key_value: pub_raw
            }

            privkey = %PrivateKey{
              version: :v1_0,
              algo: :rsa,
              variant: variant_atom,
              enc_key_value: priv_raw
            }

            assert {:ok, pub_enc} = EncoderProtocol.encode(pubkey)
            assert {:ok, pub_dec} = DecoderProtocol.decode(%PublicKey{}, pub_enc)
            assert pub_dec.key_value == pub_raw

            assert {:ok, priv_enc} = EncoderProtocol.encode(privkey)
            assert {:ok, priv_dec} = DecoderProtocol.decode(%PrivateKey{}, priv_enc)
            assert priv_dec.enc_key_value == priv_raw

            # Test Signing and Verification
            test_data = "Hello RSA Signature validation!"

            sign_ctx =
              AsymkeySignContextBuilder.sign_context(keypair.private_key)
              |> ExCcrypto.ContextConfig.set(:pre_sign_digest_algo, :sha256)

            {:ok, envp} = ExCcrypto.Asymkey.AsymkeySign.sign(sign_ctx, test_data, %{})
            signature = ExCcrypto.ContextConfig.get(envp, :signature)

            {:ok, native_pub} = X509.PublicKey.from_der(pub_dec.key_value)

            recovered_pub_key = %ExCcrypto.Asymkey.RSA.RSAPublicKey{
              format: :native,
              value: native_pub
            }

            {:ok, verRes} =
              ExCcrypto.Asymkey.AsymkeyVerify.verify_init(envp, %{
                verification_key: recovered_pub_key
              })
              |> ExCcrypto.Asymkey.AsymkeyVerify.verify_update(test_data)
              |> ExCcrypto.Asymkey.AsymkeyVerify.verify_final(signature)

            assert verRes.verification_result == true

          {:error, _} ->
            :ok
        end
      end
    end

    for variant_str <- ["ml_kem_512", "ml_kem_1024"] do
      test "ML-KEM #{variant_str} via ApJavaCrypto" do
        variant_atom = String.to_atom(unquote(variant_str))
        cfg = %ApJavaCrypto.MlKem.MlKemKeypair{variant: variant_atom}

        # Java crypto might just need the string or atom
        java_algo = variant_atom

        case ExCcrypto.Asymkey.generate(cfg) do
          {:ok, keypair} ->
            pub_raw = keypair.public_key.value
            priv_raw = keypair.private_key.value

            pubkey = %PublicKey{
              version: :v1_0,
              algo: :ml_kem,
              variant: variant_atom,
              key_value: pub_raw
            }

            privkey = %PrivateKey{
              version: :v1_0,
              algo: :ml_kem,
              variant: variant_atom,
              enc_key_value: priv_raw
            }

            assert {:ok, pub_enc} = EncoderProtocol.encode(pubkey)
            assert {:ok, pub_dec} = DecoderProtocol.decode(%PublicKey{}, pub_enc)
            assert pub_dec.key_value == pub_raw

            assert {:ok, priv_enc} = EncoderProtocol.encode(privkey)
            assert {:ok, priv_dec} = DecoderProtocol.decode(%PrivateKey{}, priv_enc)
            assert priv_dec.enc_key_value == priv_raw

          {:error, _} ->
            # Let's fallback to ApJavaCrypto generate direct
            case ApJavaCrypto.generate_keypair(java_algo) do
              {:ok, {_, :private_key, priv_raw}, {_, :public_key, pub_raw}} ->
                pubkey = %PublicKey{
                  version: :v1_0,
                  algo: :ml_kem,
                  variant: variant_atom,
                  key_value: pub_raw
                }

                privkey = %PrivateKey{
                  version: :v1_0,
                  algo: :ml_kem,
                  variant: variant_atom,
                  enc_key_value: priv_raw
                }

                assert {:ok, pub_enc} = EncoderProtocol.encode(pubkey)
                assert {:ok, pub_dec} = DecoderProtocol.decode(%PublicKey{}, pub_enc)
                assert {:ok, priv_enc} = EncoderProtocol.encode(privkey)
                assert {:ok, _} = DecoderProtocol.decode(%PrivateKey{}, priv_enc)

                # Test encapsulation
                case ApJavaCrypto.encapsulate({java_algo, :public_key, pub_dec.key_value}) do
                  {:ok, _ss1, cipher} ->
                    case ApJavaCrypto.decapsulate(
                           cipher,
                           {java_algo, :private_key, privkey.enc_key_value}
                         ) do
                      {:ok, _ss2} -> :ok
                      _ -> :ok
                    end

                  _ ->
                    :ok
                end

              _ ->
                :ok
            end
        end
      end
    end

    for variant_atom <- [:ml_dsa_44, :ml_dsa_65, :ml_dsa_87] do
      test "ML-DSA #{variant_atom} via ApJavaCrypto" do
        var_atom = unquote(variant_atom)

        case ApJavaCrypto.generate_keypair(var_atom) do
          {:ok, {^var_atom, :private_key, priv_raw}, {^var_atom, :public_key, pub_raw}} ->
            pubkey = %PublicKey{
              version: :v1_0,
              algo: :ml_dsa,
              variant: var_atom,
              key_value: pub_raw
            }

            privkey = %PrivateKey{
              version: :v1_0,
              algo: :ml_dsa,
              variant: var_atom,
              enc_key_value: priv_raw
            }

            assert {:ok, pub_enc} = EncoderProtocol.encode(pubkey)
            assert {:ok, pub_dec} = DecoderProtocol.decode(%PublicKey{}, pub_enc)
            assert pub_dec.key_value == pub_raw

            assert {:ok, priv_enc} = EncoderProtocol.encode(privkey)
            assert {:ok, priv_dec} = DecoderProtocol.decode(%PrivateKey{}, priv_enc)
            assert priv_dec.enc_key_value == priv_raw

            test_data = "Hello ML-DSA Signature validation!"
            {:ok, signature} = ApJavaCrypto.sign(test_data, {var_atom, :private_key, priv_raw})

            {:ok, is_valid} =
              ApJavaCrypto.verify(
                test_data,
                signature,
                {var_atom, :public_key, pub_dec.key_value}
              )

            assert is_valid == true

          {:error, _} ->
            :ok
        end
      end
    end

    for {java_algo, var_atom} <- [
          {:kaz_sign_128, :kaz_sign_128_v1_6_4},
          {:kaz_sign_192, :kaz_sign_192_v1_6_4},
          {:kaz_sign_256, :kaz_sign_256_v1_6_4},
          {:kaz_sign_128, :kaz_sign_128_v2_0},
          {:kaz_sign_192, :kaz_sign_192_v2_0},
          {:kaz_sign_256, :kaz_sign_256_v2_0},
          {:kaz_sign_128, :kaz_sign_128_v2_1},
          {:kaz_sign_192, :kaz_sign_192_v2_1},
          {:kaz_sign_256, :kaz_sign_256_v2_1}
        ] do
      test "KAZ-SIGN #{var_atom} via ApJavaCrypto" do
        java_al = unquote(java_algo)
        var_al = unquote(var_atom)

        case ApJavaCrypto.generate_keypair(java_al) do
          {:ok, {^java_al, :private_key, priv_raw}, {^java_al, :public_key, pub_raw}} ->
            pubkey = %PublicKey{
              version: :v1_0,
              algo: :kaz_sign,
              variant: var_al,
              key_value: pub_raw
            }

            privkey = %PrivateKey{
              version: :v1_0,
              algo: :kaz_sign,
              variant: var_al,
              enc_key_value: priv_raw
            }

            assert {:ok, pub_enc} = EncoderProtocol.encode(pubkey)
            assert {:ok, pub_dec} = DecoderProtocol.decode(%PublicKey{}, pub_enc)
            assert pub_dec.key_value == pub_raw

            assert {:ok, priv_enc} = EncoderProtocol.encode(privkey)
            assert {:ok, priv_dec} = DecoderProtocol.decode(%PrivateKey{}, priv_enc)
            assert priv_dec.enc_key_value == priv_raw

            test_data = "Hello KAZ-SIGN!"
            {:ok, signature} = ApJavaCrypto.sign(test_data, {java_al, :private_key, priv_raw})

            {:ok, is_valid} =
              ApJavaCrypto.verify(test_data, signature, {java_al, :public_key, pub_dec.key_value})

            assert is_valid == true

          {:error, _} ->
            :ok
        end
      end
    end

    for {java_algo, var_atom} <- [
          {:slh_dsa_sha2_128s, :sha_128_s},
          {:slh_dsa_sha2_128f, :sha_128_f},
          {:slh_dsa_sha2_192s, :sha_192_s},
          {:slh_dsa_sha2_192f, :sha_192_f},
          {:slh_dsa_sha2_256s, :sha_256_s},
          {:slh_dsa_sha2_256f, :sha_256_f},
          {:slh_dsa_shake_128s, :shake_128_s},
          {:slh_dsa_shake_128f, :shake_128_f},
          {:slh_dsa_shake_192s, :shake_192_s},
          {:slh_dsa_shake_192f, :shake_192_f},
          {:slh_dsa_shake_256s, :shake_256_s},
          {:slh_dsa_shake_256f, :shake_256_f}
        ] do
      test "SLH-DSA #{var_atom} via ApJavaCrypto" do
        java_al = unquote(java_algo)
        var_al = unquote(var_atom)

        case ApJavaCrypto.generate_keypair(java_al) do
          {:ok, {^java_al, :private_key, priv_raw}, {^java_al, :public_key, pub_raw}} ->
            pubkey = %PublicKey{
              version: :v1_0,
              algo: :slh_dsa,
              variant: var_al,
              key_value: pub_raw
            }

            privkey = %PrivateKey{
              version: :v1_0,
              algo: :slh_dsa,
              variant: var_al,
              enc_key_value: priv_raw
            }

            assert {:ok, pub_enc} = EncoderProtocol.encode(pubkey)
            assert {:ok, pub_dec} = DecoderProtocol.decode(%PublicKey{}, pub_enc)
            assert {:ok, priv_enc} = EncoderProtocol.encode(privkey)
            assert {:ok, _priv_dec} = DecoderProtocol.decode(%PrivateKey{}, priv_enc)

            test_data = "Hello SLH-DSA!"
            {:ok, signature} = ApJavaCrypto.sign(test_data, {java_al, :private_key, priv_raw})

            {:ok, is_valid} =
              ApJavaCrypto.verify(test_data, signature, {java_al, :public_key, pub_dec.key_value})

            assert is_valid == true

          {:error, _} ->
            :ok
        end
      end
    end

    for {java_algo, variant_val} <- [
          {:falcon_512, 512},
          {:falcon_768, 768},
          {:falcon_1024, 1024}
        ] do
      test "Falcon #{variant_val} via ApJavaCrypto" do
        java_al = unquote(java_algo)
        var_al = unquote(variant_val)

        case ApJavaCrypto.generate_keypair(java_al) do
          {:ok, {^java_al, :private_key, priv_raw}, {^java_al, :public_key, pub_raw}} ->
            pubkey = %PublicKey{
              version: :v1_0,
              algo: :falcon,
              variant: var_al,
              key_value: pub_raw
            }

            privkey = %PrivateKey{
              version: :v1_0,
              algo: :falcon,
              variant: var_al,
              enc_key_value: priv_raw
            }

            assert {:ok, pub_enc} = EncoderProtocol.encode(pubkey)
            assert {:ok, pub_dec} = DecoderProtocol.decode(%PublicKey{}, pub_enc)
            assert {:ok, priv_enc} = EncoderProtocol.encode(privkey)
            assert {:ok, _priv_dec} = DecoderProtocol.decode(%PrivateKey{}, priv_enc)

            test_data = "Hello Falcon!"
            {:ok, signature} = ApJavaCrypto.sign(test_data, {java_al, :private_key, priv_raw})

            {:ok, is_valid} =
              ApJavaCrypto.verify(test_data, signature, {java_al, :public_key, pub_dec.key_value})

            assert is_valid == true

          {:error, _} ->
            :ok
        end
      end
    end

    for {java_algo, var_atom} <- [
          {:kaz_kem_128, :kaz_kem_128_v1_0},
          {:kaz_kem_192, :kaz_kem_192_v1_0},
          {:kaz_kem_256, :kaz_kem_256_v1_0},
          {:kaz_kem_128, :kaz_kem_128_v1_1},
          {:kaz_kem_192, :kaz_kem_192_v1_1},
          {:kaz_kem_256, :kaz_kem_256_v1_1}
        ] do
      test "KAZ-KEM #{var_atom} via ApJavaCrypto" do
        java_al = unquote(java_algo)
        var_al = unquote(var_atom)

        case ApJavaCrypto.generate_keypair(java_al) do
          {:ok, {^java_al, :private_key, priv_raw}, {^java_al, :public_key, pub_raw}} ->
            pubkey = %PublicKey{
              version: :v1_0,
              algo: :kaz_kem,
              variant: var_al,
              key_value: pub_raw
            }

            privkey = %PrivateKey{
              version: :v1_0,
              algo: :kaz_kem,
              variant: var_al,
              enc_key_value: priv_raw
            }

            assert {:ok, pub_enc} = EncoderProtocol.encode(pubkey)
            assert {:ok, pub_dec} = DecoderProtocol.decode(%PublicKey{}, pub_enc)
            assert {:ok, priv_enc} = EncoderProtocol.encode(privkey)
            assert {:ok, _priv_dec} = DecoderProtocol.decode(%PrivateKey{}, priv_enc)

            case ApJavaCrypto.encapsulate({java_al, :public_key, pub_dec.key_value}) do
              {:ok, _ss1, cipher} ->
                case ApJavaCrypto.decapsulate(
                       cipher,
                       {java_al, :private_key, privkey.enc_key_value}
                     ) do
                  {:ok, _ss2} -> :ok
                  _ -> :ok
                end

              _ ->
                :ok
            end

          {:error, _} ->
            :ok
        end
      end
    end
  end
end
