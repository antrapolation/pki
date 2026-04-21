defmodule StrapPrivKeyStoreProviderProcessUserTest do
  alias StrapPrivKeyStoreProvider.CSRGenerator
  alias ExCcrypto.ContextConfig
  alias ExCcrypto.X509.X509Certificate
  alias StrapPrivKeyStoreProvider.CertManager
  alias StrapPrivKeyStoreProvider.KeystoreManager
  alias StrapPrivKeyStoreProvider.KeypairManager
  alias StrapPrivKeyStoreProvider.KeyGenerator
  alias ExCcrypto.X509.CertProfile
  alias ExCcrypto.X509.CertOwner
  alias StrapPrivKeyStoreProvider.ProcessProviderContext
  alias StrapPrivKeyStoreProvider.ProviderInfo
  use ExUnit.Case
  doctest StrapPrivKeyStoreProviderProcessUser

  test "calling software priv keystore provider process" do
    assert {:ok, ctx} =
             StrapPrivKeyStoreProvider.get_provider_context(%{
               node: :"soft_privkey_store_test@127.0.0.1",
               process_group_name: :soft_priv_key_store_test
             })

    IO.inspect(ctx)

    assert {:ok, types} =
             StrapPrivKeyStoreProvider.supported_key_types(
               ctx,
               %{
                 purpose: :sign
               }
             )

    IO.inspect(types)

    test_operations(types)
  end

  def test_operations(types) do
    Enum.each(types, fn type ->
      assert {:ok, keypair} = KeyGenerator.generate_key(type, %{timeout: 10_000})
      IO.inspect(keypair)

      assert :ok = test_for_purpose(keypair)

      assert {:ok, keystore} = KeypairManager.to_keystore(keypair, "password")

      assert {:ok, rkeypair} = KeystoreManager.to_keypair(keystore, "password")
      assert rkeypair == keypair

      assert {:error, :password_incorrect} =
               KeystoreManager.to_keypair(keystore, "wrong-password")

      assert {:ok, ukeystore} =
               KeystoreManager.update_auth_token(keystore, "password", "password2")

      assert {:ok, rkeypair2} = KeystoreManager.to_keypair(ukeystore, "password2")
      assert rkeypair2 == rkeypair

      assert {:error, :password_incorrect} =
               KeystoreManager.to_keypair(ukeystore, "password")

      assert {:ok, rkeypair3} = KeystoreManager.to_keypair(ukeystore, "password2")
      assert rkeypair3 == rkeypair2

      case keypair.purpose do
        :sign ->
          assert {:ok, keypair2} = KeyGenerator.generate_key(type, %{timeout: 10_000})
          assert {:ok, keystore2} = KeypairManager.to_keystore(keypair2, "password2")

          assert {:ok, keypair3} = KeyGenerator.generate_key(type, %{timeout: 10_000})
          assert {:ok, keystore3} = KeypairManager.to_keystore(keypair3, "password3")

          self_co =
            %CertOwner{}
            |> CertOwner.set_name(
              "Antrapolation Technology SoftKeystore Provider Test Root Issuer"
            )
            |> CertOwner.set_org("Antrapolation Technology")
            |> CertOwner.set_state_or_locality("Selangor")
            |> CertOwner.set_country("MY")

          self_issuer =
            CertProfile.self_sign_issuer_cert_config()
            |> CertProfile.set_signing_hash(:sha512)
            |> CertProfile.set_validity_period(
              {{2025, 6, 30}, {0, 0, 0}},
              {10, :year}
            )

          assert {:ok, cert} =
                   CertManager.generate_cert(ukeystore, self_co, self_issuer, %{
                     keystore_auth_token: "password2"
                   })

          IO.inspect(cert)

          with {:der, bin} <- X509Certificate.to_der(cert) do
            File.write!("rroot.crt", bin)
          end

          co =
            CertOwner.set_name(%CertOwner{}, "Antrapolation Technology Test SubIssuer CSR")
            |> CertOwner.set_org("Antrapol")
            |> CertOwner.set_email("test@test.com")
            |> CertOwner.set_country("MY")
            |> CertOwner.add_org_unit("X Division")
            |> CertOwner.add_org_unit("Enanble")
            |> CertOwner.set_public_key(ContextConfig.get(keypair2.value, :public_key))

          assert {:ok, csr} =
                   CSRGenerator.generate(keystore2, co, %{
                     keystore_auth_token: "password2"
                   })

          IO.inspect(csr)

          issuer =
            CertProfile.issuer_cert_config()
            |> CertProfile.set_signing_hash(:sha512)
            |> CertProfile.set_validity_period(
              {{2025, 6, 30}, {0, 0, 0}},
              {5, :year}
            )

          assert {:ok, cert2} =
                   CertManager.issue_cert(ukeystore, csr, issuer, %{
                     keystore_auth_token: "password2",
                     issuer_cert: cert
                   })

          IO.inspect(cert2)

          with {:der, bin} <- X509Certificate.to_der(cert2) do
            File.write!("rsub_root.crt", bin)
          end

          subco =
            CertOwner.set_name(%CertOwner{}, "Antrapol Subscriber")
            |> CertOwner.set_org("Antrapol")
            |> CertOwner.set_email("subscriber@antrapol.com")
            |> CertOwner.set_country("MY")
            |> CertOwner.add_org_unit("X Division")
            |> CertOwner.add_org_unit("Enanble")
            |> CertOwner.set_public_key(ContextConfig.get(keypair3.value, :public_key))

          assert {:ok, csr2} =
                   CSRGenerator.generate(keystore3, subco, %{
                     keystore_auth_token: "password3"
                   })

          IO.inspect(csr2)

          subscriber =
            CertProfile.leaf_cert_config()
            |> CertProfile.set_signing_hash(:sha512)
            |> CertProfile.set_validity_period(
              {{2026, 1, 31}, {0, 0, 0}},
              {47, :day}
            )

          assert {:ok, cert3} =
                   CertManager.issue_cert(keystore2, csr2, subscriber, %{
                     keystore_auth_token: "password2",
                     issuer_cert: cert2
                   })

          IO.inspect(cert3)

          with {:der, bin} <- X509Certificate.to_der(cert3) do
            File.write!("ruser.crt", bin)
          end

        _ ->
          :ok
      end
    end)
  end

  defp test_for_purpose(%{purpose: :sign} = keypair), do: sign_verify(keypair)

  defp test_for_purpose(%{purpose: :enc} = keypair), do: enc_dec(keypair)

  defp test_for_purpose(%{purpose: :sign_enc} = keypair) do
    assert :ok = sign_verify(keypair)
    assert :ok = enc_dec(keypair)
  end

  defp sign_verify(keypair) do
    data = :crypto.strong_rand_bytes(28)

    privKey = KeypairManager.private_key(keypair)
    pubKey = KeypairManager.public_key(keypair)

    assert {:ok, sign} = KeypairManager.sign_data(privKey, data)
    assert {:ok, verRes} = KeypairManager.verify_data(pubKey, data, sign)

    assert verRes.verification_result

    assert {:ok, verRes2} =
             KeypairManager.verify_data(pubKey, :crypto.strong_rand_bytes(28), sign)

    assert verRes2.verification_result == false

    :ok
  end

  defp enc_dec(keypair) do
    data = :crypto.strong_rand_bytes(28)

    privKey = KeypairManager.private_key(keypair)
    pubKey = KeypairManager.public_key(keypair)

    assert {:ok, cipher} = KeypairManager.encrypt_data(pubKey, data)
    assert {:ok, plain} = KeypairManager.decrypt_data(privKey, pubKey, cipher)
    assert plain == data

    :ok
  end
end
