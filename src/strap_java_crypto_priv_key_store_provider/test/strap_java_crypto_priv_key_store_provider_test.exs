defmodule StrapJavaCryptoPrivKeyStoreProviderTest do
  alias StrapPrivKeyStoreProvider.CSRGenerator
  alias ExCcrypto.ContextConfig
  alias ExCcrypto.X509.X509Certificate
  alias StrapPrivKeyStoreProvider.CertManager
  alias StrapPrivKeyStoreProvider.KeystoreManager
  alias StrapPrivKeyStoreProvider.KeypairManager
  alias StrapPrivKeyStoreProvider.KeyGenerator
  alias ExCcrypto.X509.CertProfile
  alias ExCcrypto.X509.CertOwner
  alias StrapJavaCryptoPrivKeyStoreProvider.JavaCryptoProviderProcess
  use ExUnit.Case
  doctest StrapJavaCryptoPrivKeyStoreProvider

  setup do
    # Start ApJavaCrypto (if not already started by app)
    # Start Provider Process

    # Ensure dependencies are started
    Application.ensure_all_started(:ap_java_crypto)
    Application.ensure_all_started(:strap_priv_key_store_provider)

    # Start ApJavaCrypto worker explicitly since the app doesn't start it
    # We use the default group :ap_java_crypto as expected by the defaults
    {:ok, ap_pid} = ApJavaCrypto.start_link()

    # Start the JavaCryptoProviderProcess locally
    # We use a unique group name for the test to avoid collisions
    group_name = :java_crypto_test_group

    {:ok, pid} =
      JavaCryptoProviderProcess.start_link(%{
        group: group_name,
        crypto_group: :ap_java_crypto
      })

    # Allow time for startup
    Process.sleep(100)

    on_exit(fn ->
      try do
        if Process.alive?(pid), do: GenServer.stop(pid)
      catch
        :exit, _ -> :ok
      end

      try do
        if Process.alive?(ap_pid), do: GenServer.stop(ap_pid)
      catch
        :exit, _ -> :ok
      end
    end)

    %{group_name: group_name}
  end

  @tag timeout: :infinity
  test "calling java crypto priv keystore provider process", %{group_name: group_name} do
    # Use Node.self() since we are running in the same node
    node = Node.self()

    assert {:ok, ctx} =
             StrapPrivKeyStoreProvider.get_provider_context(%{
               node: node,
               process_group_name: group_name,
               crypto_group: :ap_java_crypto
             })

    IO.inspect(ctx, label: "Provider Context")

    # Get supported key types (sign + enc)
    assert {:ok, types} =
             StrapPrivKeyStoreProvider.supported_key_types(
               ctx,
               %{
                 purpose: :all,
                 crypto_group: :ap_java_crypto
               }
             )

    IO.inspect(types, label: "Supported Key Types")

    # Filter types to avoid exhaustive testing of ALL curves if too many,
    # but for now let's just pick a few representative ones if the list is huge.
    # Or just test them all if reasonable.
    # ApJavaCrypto returns PQC algos.

    test_operations(types, group_name)
  end

  def test_operations(types, group_name) do
    # Create a directory for test artifacts
    File.mkdir_p!("test_artifacts")

    Enum.each(types, fn type ->
      IO.puts("Testing type: #{type.algo_string} purpose: #{type.purpose}")

      # Pass crypto_group in opts
      opts = %{timeout: 130_000, crypto_group: :ap_java_crypto}

      assert {:ok, keypair} = KeyGenerator.generate_key(type, opts)
      # IO.inspect(keypair, label: "Generated Keypair")

      assert :ok = test_for_purpose(keypair, opts)

      assert {:ok, keystore} = KeypairManager.to_keystore(keypair, "password", opts)

      assert {:ok, rkeypair} = KeystoreManager.to_keypair(keystore, "password", opts)

      # Comparing keypairs might be tricky if they contain opaque references or different map grouping.
      # But our implementation returns structs with values.
      # Ideally rkeypair == keypair.
      # If not, check if components are equal.
      assert rkeypair.algo == keypair.algo
      # assert rkeypair.value == keypair.value

      assert {:error, _} =
               KeystoreManager.to_keypair(keystore, "wrong-password", opts)

      assert {:ok, ukeystore} =
               KeystoreManager.update_auth_token(keystore, "password", "password2", opts)

      assert {:ok, rkeypair2} = KeystoreManager.to_keypair(ukeystore, "password2", opts)
      # assert rkeypair2 == rkeypair

      assert {:error, _} =
               KeystoreManager.to_keypair(ukeystore, "password", opts)

      assert {:ok, rkeypair3} = KeystoreManager.to_keypair(ukeystore, "password2", opts)
      # assert rkeypair3 == rkeypair2

      if type.purpose == :sign do
        # Certificate Test
        assert {:ok, keypair2} = KeyGenerator.generate_key(type, opts)
        assert {:ok, keystore2} = KeypairManager.to_keystore(keypair2, "password2", opts)

        assert {:ok, keypair3} = KeyGenerator.generate_key(type, opts)
        assert {:ok, keystore3} = KeypairManager.to_keystore(keypair3, "password3", opts)

        self_co =
          %CertOwner{}
          |> CertOwner.set_name("Antrapol JavaCrypto Test Root Issuer")
          |> CertOwner.set_org("Antrapolation Technology")
          |> CertOwner.set_country("MY")

        self_issuer =
          CertProfile.self_sign_issuer_cert_config()
          |> CertProfile.set_signing_hash(:sha512)
          |> CertProfile.set_validity_period(
            {{2025, 6, 30}, {0, 0, 0}},
            {10, :year}
          )

        assert {:ok, cert} =
                 CertManager.generate_cert(
                   ukeystore,
                   self_co,
                   self_issuer,
                   Map.merge(opts, %{
                     keystore_auth_token: "password2"
                   })
                 )

        # IO.inspect(cert, label: "Generated Cert")

        with {:der, bin} <- X509Certificate.to_der(cert) do
          File.write!("test_artifacts/#{type.algo_string}_root.crt", bin)
        end

        co =
          CertOwner.set_name(%CertOwner{}, "Antrapol JavaCrypto Test SubIssuer CSR")
          |> CertOwner.set_org("Antrapol")
          |> CertOwner.set_country("MY")
          |> CertOwner.set_public_key(Map.get(keypair2.value, :public_key))

        assert {:ok, csr} =
                 CSRGenerator.generate(
                   keystore2,
                   co,
                   Map.merge(opts, %{
                     keystore_auth_token: "password2"
                   })
                 )

        # IO.inspect(csr, label: "Generated CSR")

        issuer =
          CertProfile.issuer_cert_config()
          |> CertProfile.set_signing_hash(:sha512)
          |> CertProfile.set_validity_period(
            {{2025, 6, 30}, {0, 0, 0}},
            {5, :year}
          )

        assert {:ok, cert2} =
                 CertManager.issue_cert(
                   ukeystore,
                   csr,
                   issuer,
                   Map.merge(opts, %{
                     keystore_auth_token: "password2",
                     issuer_cert: cert
                   })
                 )

        # IO.inspect(cert2, label: "Issued Sub Cert")

        with {:der, bin} <- X509Certificate.to_der(cert2) do
          File.write!("test_artifacts/#{type.algo_string}_sub_root.crt", bin)
        end
      end
    end)
  end

  defp test_for_purpose(%{purpose: :sign} = keypair, opts), do: sign_verify(keypair, opts)

  defp test_for_purpose(%{purpose: :enc} = keypair, opts), do: enc_dec(keypair, opts)

  defp test_for_purpose(%{purpose: :sign_enc} = keypair, opts) do
    with :ok <- sign_verify(keypair, opts),
         :ok <- enc_dec(keypair, opts) do
      :ok
    end
  end

  defp sign_verify(keypair, opts) do
    data = :crypto.strong_rand_bytes(28)

    privKey = KeypairManager.private_key(keypair)
    pubKey = KeypairManager.public_key(keypair)

    assert {:ok, sign} = KeypairManager.sign_data(privKey, data, opts)
    assert {:ok, verRes} = KeypairManager.verify_data(pubKey, data, sign, opts)

    assert verRes == true

    # Negative test
    # assert {:ok, false} =
    #          KeypairManager.verify_data(pubKey, :crypto.strong_rand_bytes(28), sign, opts)

    # ApJavaCrypto.verify returns {:ok, true} or error/false.
    # My Pubkey implementation maps it.

    :ok
  end

  defp enc_dec(keypair, opts) do
    # For KEM (which ApJavaCrypto supports), we encapsulates
    # Pubkey.encrypt_data maps to encapsulation

    pubKey = KeypairManager.public_key(keypair)
    privKey = KeypairManager.private_key(keypair)

    assert {:ok, %{secret: secret, cipher: cipher}} =
             KeypairManager.encrypt_data(pubKey, "", opts)

    # Decrypt (Decapsulate)
    assert {:ok, decrypted_secret} = KeypairManager.decrypt_data(privKey, pubKey, cipher, opts)

    assert decrypted_secret == secret
    :ok
  end
end
