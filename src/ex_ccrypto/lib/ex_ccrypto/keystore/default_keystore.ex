defmodule ExCcrypto.Keystore.DefaultKeystore do
  # alias ExCcrypto.Asymkey.SlhDsa.SlhDsaPrivateKey
  # alias ExCcrypto.Asymkey.MlDsa.MlDsaPrivateKey
  # alias ExCcrypto.Asymkey.KazSign.KazSignPrivateKey
  alias ExCcrypto.X509.X509Certificate
  alias ExCcrypto.Asymkey.KeyEncoding
  alias ExCcrypto.Keystore.ExCcryptoKeypairstore
  alias ExCcrypto.Cipher
  alias ExCcrypto.KDF.KDFContextBuilder
  alias ExCcrypto.Cipher.CipherContextBuilder

  require Logger

  def to_keypairstore(kp, c, cc, at, opts) when not is_map(opts),
    do: to_keypairstore(kp, c, cc, at, %{})

  def to_keypairstore(keypair, cert, chain, auth_token, opts) do
    kps = ExCcryptoKeypairstore.build(keypair, cert, chain, opts)

    cond do
      is_nil(auth_token) -> {:ok, :erlang.term_to_binary(kps)}
      byte_size(auth_token) == 0 -> {:ok, :erlang.term_to_binary(kps)}
      true -> encrypt_store(:erlang.term_to_binary(kps), auth_token, opts)
    end
  end

  def to_raw_keypairstore(keypair, public_key, auth_token, opts) when not is_map(opts),
    do: to_raw_keypairstore(keypair, public_key, auth_token, %{})

  def to_raw_keypairstore(keypair, public_key, auth_token, opts) do
    kps = ExCcryptoKeypairstore.build_raw(keypair, public_key, opts)

    cond do
      is_nil(auth_token) -> {:ok, :erlang.term_to_binary(kps)}
      byte_size(auth_token) == 0 -> {:ok, :erlang.term_to_binary(kps)}
      true -> encrypt_store(:erlang.term_to_binary(kps), auth_token, opts)
    end
  end

  def to_pkcs12_keystore(keypair, cert, chain, auth_token, opts) when not is_list(chain),
    do: to_pkcs12_keystore(keypair, cert, [chain], auth_token, opts)

  #  def to_pkcs12_keystore(
  #        key,
  #        {:der, {:ap_java_crypto, cert}},
  #        chain,
  #        auth_token,
  #        opts
  #      ) do
  #    Logger.debug("P12 to ApJavaCrypto")
  #    name = Map.get(opts, :name, "P12 Keystore")
  #
  #    cchain =
  #      Enum.map(chain, fn c ->
  #        {:der, {:ap_java_crypto, cb}} = c
  #        {:der, cb}
  #      end)
  #
  #    ApJavaCrypto.generate_p12(
  #      name,
  #      {key.variant, :private_key, key.value},
  #      {:der, cert},
  #      cchain,
  #      %{
  #        store_pass: auth_token
  #      }
  #    )
  #  end

  def to_pkcs12_keystore(keypair, cert, chain, auth_token, _opts) do
    Logger.debug("Native P12")

    tmp_root = System.tmp_dir() || System.get_env("EXCCRYPTO_TMP_DIR") || "."
    residual = []

    Logger.debug("tmp_root : #{inspect(tmp_root)}")

    {:ok, privkey} = KeyEncoding.encode(keypair, :pem)
    full_tmp_key = Path.join([tmp_root, Base.encode16(:crypto.strong_rand_bytes(24))])
    File.write(full_tmp_key, privkey.value)
    File.chmod(full_tmp_key, 0o600)
    Logger.debug("full_tmp_key : #{inspect(full_tmp_key)}")

    residual = [full_tmp_key | residual]

    full_tmp_cert = Path.join([tmp_root, Base.encode16(:crypto.strong_rand_bytes(24))])
    residual = [full_tmp_cert | residual]
    Logger.debug("full_tmp_cert : #{inspect(full_tmp_cert)}")

    # File.write!(
    #  full_tmp_cert,
    #  "-----BEGIN CERTIFICATE-----\n#{X509.Certificate.to_pem(cert)}-----END CERTIFICATE-----\n"
    # )
    {:pem, cert_pem} = X509Certificate.to_pem(cert)

    File.write!(
      full_tmp_cert,
      cert_pem
      # "-----BEGIN CERTIFICATE-----\n#{X509Certificate.to_pem(cert)}-----END CERTIFICATE-----\n"
      # "-----BEGIN CERTIFICATE-----\n#{cert_pem}-----END CERTIFICATE-----\n"
    )
    File.chmod(full_tmp_cert, 0o600)

    full_tmp_chain = Path.join([tmp_root, Base.encode16(:crypto.strong_rand_bytes(24))])
    Logger.debug("full_tmp_chain : #{inspect(full_tmp_chain)}")

    {:ok, chain_file} = File.open(full_tmp_chain, [:write])
    File.chmod(full_tmp_chain, 0o600)

    Enum.map(chain, fn c ->
      {:pem, ccpem} = X509Certificate.to_pem(c)

      IO.write(
        chain_file,
        ccpem
        # "-----BEGIN CERTIFICATE-----\n#{X509Certificate.to_pem(c)}-----END CERTIFICATE-----\n"
        # "-----BEGIN CERTIFICATE-----\n#{ccpem}-----END CERTIFICATE-----\n"
      )
    end)

    File.close(chain_file)
    residual = [full_tmp_chain | residual]

    full_tmp_out = Path.join([tmp_root, Base.encode16(:crypto.strong_rand_bytes(24))])
    residual = [full_tmp_out | residual]
    Logger.debug("full_tmp_out : #{inspect(full_tmp_out)}")

    res =
      System.cmd("openssl", [
        "pkcs12",
        "-export",
        "-inkey",
        full_tmp_key,
        "-in",
        full_tmp_cert,
        "-certfile",
        full_tmp_chain,
        "-out",
        full_tmp_out,
        "-password",
        "pass:#{auth_token}"
      ])

    Logger.debug("p12 generation result : #{inspect(res)}")

    if File.exists?(full_tmp_out), do: File.chmod(full_tmp_out, 0o600)
    p12bin = File.read!(full_tmp_out)

    Enum.map(residual, fn file ->
      File.rm(file)
      Logger.debug("Deleted #{file}")
    end)

    {:ok, p12bin}
  end

  # def load_pkcs12_keystore({:ap_java_crypto, keystore}, auth_token, _opts \\ %{}) do
  def load_pkcs12_keystore(_ks, _auth_token, _opts \\ %{}) do
    {:error, :load_pkcs12_not_supported}
    #  with {:ok, cont} <- ApJavaCrypto.load_p12(keystore, %{store_pass: auth_token}) do
    #    {:ok,
    #     Enum.map(cont, fn r ->
    #       %{
    #         r
    #         | key: to_private_key(r.key),
    #           cert: {:der, {:ap_java_crypto, r.cert}},
    #           chain: Enum.map(r.chain, fn c -> {:der, {:ap_java_crypto, c}} end)
    #       }
    #     end)}
    #  end
  end

  # defp to_private_key(%{algo: algo, value: value}) do
  #  talgo = String.downcase(to_string(algo))

  #  cond do
  #    String.starts_with?(talgo, "kaz-sign") ->
  #      KazSignPrivateKey.new(String.to_atom(talgo), value)

  #    String.starts_with?(talgo, "ml-dsa") ->
  #      MlDsaPrivateKey.new(String.to_atom(talgo), value)

  #    String.starts_with?(talgo, "slh-dsa") ->
  #      SlhDsaPrivateKey.new(String.to_atom(talgo), value)

  #    true ->
  #      raise "Unsupported private key algo : #{talgo}"
  #  end
  # end

  # defp to_private_key(%{algo: :"KAZ-SIGN-128", value: value}),
  #  do: KazSignPrivateKey.new(:kaz_sign_128, value)

  # defp to_private_key(%{algo: :"KAZ-SIGN-192", value: value}),
  #  do: KazSignPrivateKey.new(:kaz_sign_192, value)

  # defp to_private_key(%{algo: :"KAZ-SIGN-256", value: value}),
  #  do: KazSignPrivateKey.new(:kaz_sign_256, value)

  # defp to_private_key(%{algo: :"KAZ-SIGN-256", value: value}),
  #  do: KazSignPrivateKey.new(:kaz_sign_256, value)

  # 
  # Custom keystore format
  #
  defp encrypt_store(store, auth_token, opts) when is_binary(store) do
    enc_algo = Map.get(opts, :enc_algo, :aes_256_gcm)
    kdf_config = Map.get(opts, :kdf_config, KDFContextBuilder.kdf_context(:argon2))

    {:ok, %{cipher: cipher, cipher_context: context}} =
      CipherContextBuilder.user_key_cipher_context(enc_algo, auth_token, %{
        kdf_context: kdf_config
      })
      |> Cipher.cipher_init()
      |> Cipher.cipher_update(store)
      |> Cipher.cipher_final()

    {:ok, :erlang.term_to_binary(%{encrypted_keystore: cipher, encryption_context: context})}
  end

  def load_keystore(keystore_bin, auth_token \\ nil) do
    envp = :erlang.binary_to_term(keystore_bin)

    case envp do
      {:ok, %ExCcryptoKeypairstore{} = store} ->
        {:ok, store}

      %{encrypted_keystore: cipher, encryption_context: ctx} ->
        decrypt_keystore(cipher, ctx, auth_token)
    end
  end

  defp decrypt_keystore(cipher, context, auth_token) do
    with {:ok, plain} <-
           Cipher.cipher_init(context, %{password: auth_token})
           |> Cipher.cipher_update(cipher)
           |> Cipher.cipher_final() do
      :erlang.binary_to_term(plain)
    else
      {:error, :decryption_failed} -> {:error, :password_incorrect}
      res -> res
    end
  end
end
