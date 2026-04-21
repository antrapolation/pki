defmodule StrapCiphagile.Context.SymkeyCipherTest do
  use ExUnit.Case

  alias ElixirLS.LanguageServer.Parser.Context
  alias ExCcrypto.ContextConfig
  alias StrapCiphagile.Context.SymkeyCipher
  alias StrapCiphagile.Context.Symkey
  alias StrapCiphagile.Context.KDF
  alias StrapCiphagile.Context.Argon2Config
  alias StrapCiphagile.EncoderProtocol
  alias StrapCiphagile.DecoderProtocol

  alias ExCcrypto.Cipher.CipherContextBuilder
  alias ExCcrypto.Cipher
  alias ExCcrypto.KDF.KDFContextBuilder

  @test_dir "test_artifact"

  setup_all do
    {:ok, ap_java_crypto_pid} = ApJavaCrypto.start_link()
    Process.sleep(1000)
    File.mkdir_p!(@test_dir)
    %{run_id: nil, ap_java_crypto_pid: ap_java_crypto_pid}
  end

  # --- ARTIFACT GENERATOR ---

  test "generate symkey_cipher test artifacts for AES-256-GCM", %{ap_java_crypto_pid: _pid} do
    generate_symkey_cipher()
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

  defp generate_symkey_cipher() do
    plaintext = "Secret test message for AES-GCM"
    key = :crypto.strong_rand_bytes(32)

    ctx =
      CipherContextBuilder.cipher_context(:aes_256_gcm)
      |> ExCcrypto.ContextConfig.set(:session_key, key)

    {:ok, result} =
      Cipher.cipher_init(ctx, %{})
      |> Cipher.cipher_update(plaintext)
      |> Cipher.cipher_final()

    %{cipher: cipher_bin, cipher_context: envp} = result
    iv = ExCcrypto.ContextConfig.get(envp, :iv, <<>>)
    tag = ExCcrypto.ContextConfig.get(envp, :tag, <<>>)

    symkey = %Symkey{
      version: :v1_0,
      algo: :aes,
      variant: :aes_256,
      raw_key: key
    }

    symkey_cipher = %SymkeyCipher{
      version: :v1_0,
      mode: :gcm,
      symkey: symkey,
      iv: iv,
      tag: tag,
      aad: nil,
      cipher: cipher_bin
    }

    {:ok, encoded} = StrapCiphagile.encode(symkey_cipher)
    save_artifact("symkey_cipher_aes_256_gcm", %{plaintext: plaintext, key: key}, encoded)
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

      input_data =
        Map.new(input_data, fn {k, v} ->
          case Base.decode64(v) do
            {:ok, decoded} -> {k, decoded}
            :error -> {k, v}
          end
        end)

      validate_symkey_cipher(decoded_struct, input_data)
    end
  end

  defp validate_symkey_cipher(%SymkeyCipher{} = symkey_cipher, input_data) do
    case symkey_cipher.symkey.algo do
      :aes ->
        cipher_variant = String.to_atom("#{symkey_cipher.symkey.algo}_256_#{symkey_cipher.mode}")

        ctx =
          CipherContextBuilder.cipher_context(cipher_variant)
          |> ExCcrypto.ContextConfig.set(:session_key, symkey_cipher.symkey.raw_key)
          |> ExCcrypto.ContextConfig.set(:cipher_ops, :decrypt)
          |> ExCcrypto.ContextConfig.set(:iv, symkey_cipher.iv)
          |> ExCcrypto.ContextConfig.set(:tag, symkey_cipher.tag)

        assert dec_ctx = Cipher.cipher_init(ctx, %{operation: :decrypt})
        dec_ctx = Cipher.cipher_update(dec_ctx, symkey_cipher.cipher)
        assert {:ok, decrypted} = Cipher.cipher_final(dec_ctx)

        assert decrypted == input_data["plaintext"]

      _ ->
        :ok
    end
  end

  @supported_ciphers :crypto.supports(:ciphers) |> Enum.map(&to_string/1)

  # Helper to check if a cipher is supported
  defp cipher_supported?(cipher_atom) do
    Enum.member?(@supported_ciphers, to_string(cipher_atom))
  end

  # Test vectors
  # AES
  @aes_vectors (for size <- [128, 192, 256], mode <- [:cbc, :gcm, :xts] do
                  %{
                    name: "AES-#{size}-#{String.upcase(to_string(mode))}",
                    algo: :aes,
                    variant: String.to_atom("aes_#{size}"),
                    mode: mode,
                    # Construction of ExCcrypto cipher name:
                    # :aes_128_cbc, :aes_256_gcm, etc.
                    cipher: String.to_atom("aes_#{size}_#{mode}"),
                    keysize: div(size, 8)
                  }
                end)

  # Camellia
  @camellia_vectors (for size <- [128, 192, 256], mode <- [:cbc, :gcm, :xts] do
                       %{
                         name: "Camellia-#{size}-#{String.upcase(to_string(mode))}",
                         algo: :camelia,
                         variant: String.to_atom("camelia_#{size}"),
                         mode: mode,
                         # ExCcrypto/OpenSSL usually uses "camellia" with double 'l'
                         cipher: String.to_atom("camellia_#{size}_#{mode}"),
                         keysize: div(size, 8)
                       }
                     end)

  # ChaCha20-Poly1305
  @chacha_vectors [
    %{
      name: "ChaCha20-Poly1305",
      algo: :chacha20,
      # Variant usually ignored or generic
      variant: :chacha20,
      # Treated as AEAD mode often
      mode: :gcm,
      cipher: :chacha20_poly1305,
      keysize: 32
    }
  ]

  @all_vectors @aes_vectors ++ @camellia_vectors ++ @chacha_vectors

  @tag :integration
  test "end-to-end encryption/decryption with SymkeyCipher encoding" do
    # 1. Setup Encryption
    plaintext = "This is a secret message."

    # Generate random key explicitly
    # AES-256 requires 32 bytes
    input_key = :crypto.strong_rand_bytes(32)

    # Use AES-256-GCM
    ctx =
      CipherContextBuilder.default_cipher_context()
      |> ExCcrypto.ContextConfig.set(:session_key, input_key)

    # Initialize generates random IV (key is already set)
    ctx = Cipher.cipher_init(ctx, %{})

    # Encrypt
    ctx = Cipher.cipher_update(ctx, plaintext)
    {:ok, result} = Cipher.cipher_final(ctx)

    %{cipher: cipher_bin, cipher_context: envp} = result

    # 2. Construct Symkey and SymkeyCipher
    symkey = %Symkey{
      version: :v1_0,
      algo: :aes,
      variant: :aes_256,
      raw_key: input_key
    }

    IO.puts("envp : #{inspect(envp)}")

    iv = ExCcrypto.ContextConfig.get(envp, :iv, <<>>)
    tag = ExCcrypto.ContextConfig.get(envp, :tag, <<>>)

    IO.puts("tag : #{inspect(tag)}")

    symkey_cipher = %SymkeyCipher{
      version: :v1_0,
      mode: :gcm,
      symkey: symkey,
      iv: iv,
      tag: tag,
      aad: nil,
      cipher: cipher_bin
    }

    IO.puts("symkey_cipher : #{inspect(symkey_cipher)}")

    # 3. Encode SymkeyCipher
    # Use StrapCiphagile.encode to include magic tag
    assert {:ok, encoded} = StrapCiphagile.encode(symkey_cipher)

    # Verify magic tag 0xAF08, version 0x01, and outer tag 0x0A (symkey_cipher)
    assert <<0xAF, 0x08, 0x01, 0x0A, _rest::binary>> = encoded

    # 4. Decode SymkeyCipher
    # Use StrapCiphagile.decode/1
    assert {:ok, decoded} = StrapCiphagile.decode(encoded)

    assert %SymkeyCipher{} = decoded
    assert decoded.version == :v1_0
    assert decoded.mode == :gcm
    assert decoded.cipher == cipher_bin
    # Check if iv and tag are restored
    assert decoded.iv == iv
    assert decoded.tag == tag

    # Check Symkey
    decoded_symkey = decoded.symkey
    assert decoded_symkey.algo == :aes
    assert decoded_symkey.raw_key == input_key

    # 5. Decrypt using restored data
    decryption_opts = %{session_key: decoded_symkey.raw_key}

    # Manually recreate ExCcrypto context
    revived_ctx =
      CipherContextBuilder.cipher_context(:aes_256_gcm)
      |> ExCcrypto.ContextConfig.set(:cipher_ops, :decrypt)
      |> ExCcrypto.ContextConfig.set(:session_key, decoded_symkey.raw_key)
      |> ExCcrypto.ContextConfig.set(:iv, decoded.iv)
      |> ExCcrypto.ContextConfig.set(:tag, decoded.tag)

    init_ext_opts = %{operation: :decrypt}

    init_ext_opts =
      if decoded.iv != nil and decoded.iv != <<>>,
        do: Map.put(init_ext_opts, :iv, decoded.iv),
        else: init_ext_opts

    init_ext_opts =
      if decoded.tag != nil and decoded.tag != <<>>,
        do: Map.put(init_ext_opts, :tag, decoded.tag),
        else: init_ext_opts

    init_res = Cipher.cipher_init(revived_ctx, init_ext_opts)

    assert %{} = dec_ctx = init_res

    dec_ctx = Cipher.cipher_update(dec_ctx, decoded.cipher)

    assert {:ok, decrypted} = Cipher.cipher_final(dec_ctx)

    assert decrypted == plaintext
  end

  # Parameterized tests
  for vector <- @all_vectors do
    @vector vector
    test "SymkeyCipher #{@vector.name} flow" do
      if cipher_supported?(@vector.cipher) do
        run_cipher_test(@vector)
      else
        IO.puts("Skipping unsupported cipher: #{@vector.cipher}")
      end
    end
  end

  defp run_cipher_test(vector) do
    plaintext = "Secret data for #{vector.name}."

    # 1. Generate Key
    key = :crypto.strong_rand_bytes(vector.keysize)

    # 2. Setup Encryption Context
    # We need to construct context dynamically. CipherContextBuilder.cipher_context(atom)
    ctx_res = CipherContextBuilder.cipher_context(vector.cipher)

    # Check if context creation succeeded (it might fail if ExCcrypto doesn't know it, even if :crypto supports it)
    case ctx_res do
      {:error, _reason} ->
        IO.puts("ExCcrypto builder failed for #{vector.cipher}, skipping.")
        :ok

      ctx ->
        ctx = ExCcrypto.ContextConfig.set(ctx, :session_key, key)

        # Initialize
        assert {:ok, result} =
                 Cipher.cipher_init(ctx, %{})
                 |> Cipher.cipher_update(plaintext)
                 |> Cipher.cipher_final()

        # Result map format differs slightly for Block vs AEAD/GCM in some implementations?
        # ExCcrypto seems consistent: %{cipher: ..., cipher_context: ...}

        %{cipher: cipher_bin, cipher_context: envp} = result

        iv = Map.get(envp.session_data || %{}, :iv, nil)
        tag = Map.get(envp.session_data || %{}, :tag, nil)

        # 3. Construct SymkeyCipher
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

        # 4. Encode & Decode
        assert {:ok, encoded} = StrapCiphagile.encode(symkey_cipher)
        assert <<0xAF, 0x08, 0x01, 0x0A, _::binary>> = encoded

        assert {:ok, decoded} = StrapCiphagile.decode(encoded)
        assert decoded.mode == vector.mode

        # 5. Decrypt
        dec_opts = %{session_key: decoded.symkey.raw_key}

        revived_ctx =
          CipherContextBuilder.cipher_context(vector.cipher)
          |> ContextConfig.set(:iv, decoded.iv)

        revived_ctx =
          case decoded.tag do
            nil -> revived_ctx
            tag -> ContextConfig.set(revived_ctx, :tag, tag)
          end

        # |> ContextConfig.set(:tag, decoded.tag)

        IO.inspect(revived_ctx)

        revived_ctx =
          ExCcrypto.ContextConfig.set(revived_ctx, :session_key, decoded.symkey.raw_key)

        revived_ctx = ExCcrypto.ContextConfig.set(revived_ctx, :cipher_ops, :decrypt)

        init_ext_opts = %{operation: :decrypt}

        init_res = Cipher.cipher_init(revived_ctx, init_ext_opts)

        # Handle potential error in init
        case init_res do
          {:error, reason} ->
            flunk("Decryption init failed for #{vector.name}: #{inspect(reason)}")

          dec_ctx ->
            dec_ctx = Cipher.cipher_update(dec_ctx, decoded.cipher)

            # Block ciphers like CBC return `%{cipher: binary}` just like GCM in ExCcrypto
            assert {:ok, decrypted} = Cipher.cipher_final(dec_ctx)
            assert decrypted == plaintext
        end
    end
  end

  test "User Cipher Key Operation (Helper)" do
    # 0. Configuration
    password = "MyHelperPassword456!"
    plaintext = "This message is encrypted using the helper function."

    # 1. Create Context using Helper
    # This automatically derives the key using Argon2 (default) and sets it in the context
    # It also stores the KDF context (with the generated salt) in session_data
    assert {:ok, enc_result} =
             CipherContextBuilder.user_key_cipher_context(:aes_256_gcm, password)
             |> Cipher.cipher_init()
             |> Cipher.cipher_update(plaintext)
             |> Cipher.cipher_final()

    %{cipher: cipher_bin, cipher_context: envp} = enc_result

    # 2. Extract KDF Context
    # The helper stores the specific KDF context used (including salt) in the session data
    kdf_ctx = ExCcrypto.ContextConfig.get(envp, :user_key_kdf_context)

    assert kdf_ctx != nil
    assert kdf_ctx.salt != nil

    # 3. Construct SymkeyCipher
    # Map ExCcrypto Argon2Context to StrapCiphagile Argon2Config
    # Note: Values in ExCcrypto context are integers/binaries as per its definition
    # StrapCiphagile expects specific binary formats for some fields or handles them in encoder

    argon2_config = %Argon2Config{
      iteration: kdf_ctx.time_cost |> :binary.encode_unsigned(),
      cost: kdf_ctx.memory_cost |> :binary.encode_unsigned(),
      parallel: kdf_ctx.parallel |> :binary.encode_unsigned(),
      salt: kdf_ctx.salt,
      out_length: kdf_ctx.out_length |> :binary.encode_unsigned()
    }

    kdf_wrapper = %KDF{
      version: :v1_0,
      algo: :kdf,
      variant: :argon2,
      kdf_config: argon2_config,
      input: nil
    }

    symkey = %Symkey{
      version: :v1_0,
      algo: :aes,
      variant: :aes_256,
      kdf_config: kdf_wrapper,
      raw_key: nil
    }

    iv = Map.get(envp.session_data, :iv, nil)
    tag = Map.get(envp.session_data, :tag, nil)

    symkey_cipher = %SymkeyCipher{
      version: :v1_0,
      mode: :gcm,
      symkey: symkey,
      iv: iv,
      tag: tag,
      aad: nil,
      cipher: cipher_bin
    }

    # 4. Encode & Decode
    assert {:ok, encoded} = StrapCiphagile.encode(symkey_cipher)
    assert {:ok, decoded} = StrapCiphagile.decode(encoded)

    assert decoded.tag == tag
    assert decoded.iv == iv

    # 5. Decrypt using Helper-derived info
    decoded_config = decoded.symkey.kdf_config.kdf_config

    # Verify salt matches
    assert decoded_config.salt == kdf_ctx.salt

    # Re-derive
    # We can manually reconstruct the KDF context or use the builder again with explicit salt
    iter = :binary.decode_unsigned(decoded_config.iteration)
    mem = :binary.decode_unsigned(decoded_config.cost)
    par = :binary.decode_unsigned(decoded_config.parallel)
    len = :binary.decode_unsigned(decoded_config.out_length)

    re_kdf_ctx =
      KDFContextBuilder.kdf_context(:argon2)
      |> ExCcrypto.ContextConfig.set(:salt, decoded_config.salt)
      |> ExCcrypto.ContextConfig.set(:out_length, len)
      |> ExCcrypto.ContextConfig.set(:time_cost, iter)
      |> ExCcrypto.ContextConfig.set(:memory_cost, mem)
      |> ExCcrypto.ContextConfig.set(:parallel, par)

    re_derived = ExCcrypto.KDF.derive!(re_kdf_ctx, password)
    re_key = ExCcrypto.ContextConfig.get(re_derived, :derived_value)

    # Decrypt
    dec_opts = %{session_key: re_key}

    revived_ctx =
      CipherContextBuilder.cipher_context(:aes_256_gcm)
      |> ExCcrypto.ContextConfig.set(:session_key, re_key)
      |> ExCcrypto.ContextConfig.set(:cipher_ops, :decrypt)
      |> ExCcrypto.ContextConfig.set(:iv, decoded.iv)
      |> ExCcrypto.ContextConfig.set(:tag, decoded.tag)

    init_ext_opts = %{operation: :decrypt}

    assert {:ok, decrypted} =
             Cipher.cipher_init(revived_ctx, %{password: password})
             |> Cipher.cipher_update(decoded.cipher)
             |> Cipher.cipher_final()

    assert decrypted == plaintext
  end

  test "decode with random data at the back" do
    # Create a simple SymkeyCipher struct
    key = :crypto.strong_rand_bytes(32)

    symkey = %Symkey{
      version: :v1_0,
      algo: :aes,
      variant: :aes_256,
      raw_key: key
    }

    symkey_cipher = %SymkeyCipher{
      version: :v1_0,
      mode: :gcm,
      symkey: symkey,
      iv: :crypto.strong_rand_bytes(12),
      tag: :crypto.strong_rand_bytes(16),
      aad: nil,
      cipher: "cipher_text"
    }

    {:ok, encoded} = EncoderProtocol.encode(symkey_cipher)
    random_garbage = :crypto.strong_rand_bytes(10)
    full_binary = encoded <> random_garbage

    # DecoderProtocol returns {:ok, {struct, rest}} if rest not empty
    assert {:ok, {decoded_cipher, rest}} = DecoderProtocol.decode(%SymkeyCipher{}, full_binary)
    assert decoded_cipher.mode == :gcm
    assert decoded_cipher.symkey.algo == :aes
    assert rest == random_garbage
  end
end
