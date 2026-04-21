defmodule StrapCiphagile.Context.HashingArtifactGeneratorTest do
  use ExUnit.Case
  alias StrapCiphagile.Context.Hashing
  alias StrapCiphagile.EncoderProtocol

  @test_dir "test_artifact"

  setup_all do
    {:ok, ap_java_crypto_pid} = ApJavaCrypto.start_link()
    Process.sleep(1000)
    File.mkdir_p!(@test_dir)
    %{run_id: nil, ap_java_crypto_pid: ap_java_crypto_pid}
  end

  # --- ARTIFACT GENERATOR ---

  test "generate hashing test artifacts for ALL supported algorithms", %{ap_java_crypto_pid: _pid} do
    generate_sha2_artifacts()
    generate_sha3_artifacts()
    generate_photon_artifacts()
    generate_spongent_artifacts()
    generate_ripemd_artifacts()
    generate_sm3_artifacts()
    generate_acson_artifacts()
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

  # === SHA-2 ===

  defp generate_sha2_artifacts do
    data = "test content for hashing"
    salt = :crypto.strong_rand_bytes(16)

    # ExCcrypto supports: sha224, sha256, sha384, sha512
    # SHA2-512/224 and SHA2-512/256 are not supported, use random bytes
    sha2_variants = [
      {:sha2_224, :sha224, 28},
      {:sha2_256, :sha256, 32},
      {:sha2_384, :sha384, 48},
      {:sha2_512, :sha512, 64},
      {:sha2_512_224, nil, 28},
      {:sha2_512_256, nil, 32}
    ]

    for {variant, algo, hash_size} <- sha2_variants do
      actual_digest =
        if algo do
          ctx = %ExCcrypto.Digest.DigestContext{algo: algo}
          {:ok, %{digested: digest}} = ExCcrypto.Digest.digest(ctx, data <> salt)
          digest
        else
          # Use random bytes for unsupported variants
          :crypto.strong_rand_bytes(hash_size)
        end

      hash_ctx = %Hashing{
        version: :v1_0,
        algo: :sha2,
        variant: variant,
        salt: salt,
        digest: actual_digest
      }

      {:ok, encoded} = StrapCiphagile.encode(hash_ctx)
      save_artifact("hashing_sha2_#{variant}", %{data: data, salt: salt}, encoded)
    end
  end

  # === SHA-3 ===

  defp generate_sha3_artifacts do
    data = "test content for hashing"
    salt = :crypto.strong_rand_bytes(16)

    # ExCcrypto supports: sha3_224, sha3_256, sha3_384, sha3_512
    # SHA3-512/224 and SHA3-512/256 are not supported, use random bytes
    sha3_variants = [
      {:sha3_224, :sha3_224, 28},
      {:sha3_256, :sha3_256, 32},
      {:sha3_384, :sha3_384, 48},
      {:sha3_512, :sha3_512, 64},
      {:sha3_512_224, nil, 28},
      {:sha3_512_256, nil, 32}
    ]

    for {variant, algo, hash_size} <- sha3_variants do
      actual_digest =
        if algo do
          ctx = %ExCcrypto.Digest.DigestContext{algo: algo}
          {:ok, %{digested: digest}} = ExCcrypto.Digest.digest(ctx, data <> salt)
          digest
        else
          :crypto.strong_rand_bytes(hash_size)
        end

      hash_ctx = %Hashing{
        version: :v1_0,
        algo: :sha3,
        variant: variant,
        salt: salt,
        digest: actual_digest
      }

      {:ok, encoded} = StrapCiphagile.encode(hash_ctx)
      save_artifact("hashing_sha3_#{variant}", %{data: data, salt: salt}, encoded)
    end
  end

  # === PHOTON (post-quantum) - use random bytes for digest ===

  defp generate_photon_artifacts do
    data = "test content for hashing"
    salt = :crypto.strong_rand_bytes(16)

    photon_variants = [
      {:photon_80, 10},
      {:photon_128, 16},
      {:photon_160, 20},
      {:photon_224, 28},
      {:photon_256, 32}
    ]

    for {variant, hash_size} <- photon_variants do
      # Generate random bytes matching expected hash size
      actual_digest = :crypto.strong_rand_bytes(hash_size)

      hash_ctx = %Hashing{
        version: :v1_0,
        algo: :photon,
        variant: variant,
        hash_size: hash_size,
        salt: salt,
        digest: actual_digest
      }

      {:ok, encoded} = StrapCiphagile.encode(hash_ctx)
      save_artifact("hashing_photon_#{variant}", %{data: data, salt: salt}, encoded)
    end
  end

  # === SPONGENT (post-quantum) - use random bytes for digest ===

  defp generate_spongent_artifacts do
    data = "test content for hashing"
    salt = :crypto.strong_rand_bytes(16)

    spongent_variants = [
      {:spongent_88, 11},
      {:spongent_128, 16},
      {:spongent_160, 20},
      {:spongent_224, 28},
      {:spongent_256, 32}
    ]

    for {variant, hash_size} <- spongent_variants do
      actual_digest = :crypto.strong_rand_bytes(hash_size)

      hash_ctx = %Hashing{
        version: :v1_0,
        algo: :spongent,
        variant: variant,
        hash_size: hash_size,
        salt: salt,
        digest: actual_digest
      }

      {:ok, encoded} = StrapCiphagile.encode(hash_ctx)
      save_artifact("hashing_spongent_#{variant}", %{data: data, salt: salt}, encoded)
    end
  end

  # === RIPEMD ===

  defp generate_ripemd_artifacts do
    data = "test content for hashing"
    salt = :crypto.strong_rand_bytes(16)

    ripemd_variants = [
      {:ripemd_128, 16},
      {:ripemd_160, 20},
      {:ripemd_256, 32},
      {:ripemd_320, 40}
    ]

    # RIPEMD not available in ExCcrypto, use random bytes for digest
    for {variant, hash_size} <- ripemd_variants do
      actual_digest = :crypto.strong_rand_bytes(hash_size)

      hash_ctx = %Hashing{
        version: :v1_0,
        algo: :ripemd,
        variant: variant,
        hash_size: hash_size,
        salt: salt,
        digest: actual_digest
      }

      {:ok, encoded} = StrapCiphagile.encode(hash_ctx)
      save_artifact("hashing_ripemd_#{variant}", %{data: data, salt: salt}, encoded)
    end
  end

  # === SM3 (Chinese hash standard) ===

  defp generate_sm3_artifacts do
    data = "test content for hashing"
    salt = :crypto.strong_rand_bytes(16)

    # SM3 not available in ExCcrypto, use random bytes for digest
    actual_digest = :crypto.strong_rand_bytes(32)

    hash_ctx = %Hashing{
      version: :v1_0,
      algo: :sm3,
      variant: :sm3,
      hash_size: 32,
      salt: salt,
      digest: actual_digest
    }

    {:ok, encoded} = StrapCiphagile.encode(hash_ctx)
    save_artifact("hashing_sm3", %{data: data, salt: salt}, encoded)
  end

  # === ACSON (post-quantum) - use random bytes for digest ===

  defp generate_acson_artifacts do
    data = "test content for hashing"
    salt = :crypto.strong_rand_bytes(16)

    acson_variants = [
      {:acson_128, 16},
      {:acson_128a, 16},
      {:acson_hash256, 32},
      {:acson_xof128, nil},
      {:acson_cxof128, nil}
    ]

    for {variant, hash_size} <- acson_variants do
      # XOF variants have variable output, use 32 bytes for artifact
      actual_digest =
        if hash_size,
          do: :crypto.strong_rand_bytes(hash_size),
          else: :crypto.strong_rand_bytes(32)

      hash_ctx = %Hashing{
        version: :v1_0,
        algo: :acson,
        variant: variant,
        hash_size: hash_size,
        salt: salt,
        digest: actual_digest
      }

      {:ok, encoded} = StrapCiphagile.encode(hash_ctx)
      save_artifact("hashing_acson_#{variant}", %{data: data, salt: salt}, encoded)
    end
  end
end
