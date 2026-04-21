defmodule SlhDsaTest do
  alias ExCcrypto.Asymkey.SlhDsa.SlhDsaKeypair
  alias ExCcrypto.ContextConfig
  alias ExCcrypto.X509.CertGenerator
  alias ExCcrypto.X509.CertProfile
  alias ExCcrypto.X509.CertOwner
  alias StrapPrivateKeystore.KeystoreManager
  alias StrapPrivateKeystore.KeypairManager
  alias StrapSoftPrivateKeystore.SoftKeyGeneratorSpec
  alias StrapPrivateKeystore.KeyGenerator
  use ExUnit.Case

  test "SLH-DSA full operation via protocol API" do
    var = ContextConfig.get(%SlhDsaKeypair{}, :supported_variant)

    Enum.each(var, fn v ->
      IO.puts("Testing SLH-DSA variant : #{v}")

      assert {:ok, skeypair} =
               KeyGenerator.generate_keypair(SoftKeyGeneratorSpec.new(:slh_dsa, v))

      IO.inspect(skeypair)

      assert {:ok, skeystore} = KeypairManager.to_keystore(skeypair, "p@ssw0rd")

      assert {:ok, rskeypair} = KeystoreManager.keystore_to_keypair(skeystore, "p@ssw0rd")

      assert rskeypair.keypair == skeypair.keypair

      data = "This is data to be signed"

      assert {:ok, signature} = KeypairManager.sign_data(rskeypair, data)

      assert {:ok, veres} = KeypairManager.verify_data(skeypair, data, signature)

      IO.inspect(veres)

      assert veres.verification_result

      # assert {:ok, cipher} = KeypairManager.encrypt_data(skeypair, data)

      # assert plain = KeypairManager.decrypt_data(rskeypair, cipher)

      # assert plain == data

      assert {:ok, kp1} = KeypairManager.open(skeypair)
      assert kp1 == skeypair

      assert {:ok, kp2} = KeypairManager.open2(rskeypair, nil)
      assert kp2 == rskeypair

      assert {:ok, kp3} = KeypairManager.close(skeypair)
      assert kp3 == skeypair

      root_co =
        %CertOwner{}
        |> CertOwner.set_name("Soft SLH-DSA Private Keystore Cert Test")
        |> CertOwner.set_org("Antrapol")
        |> CertOwner.set_email("root@issuer.com")
        |> CertOwner.set_state_or_locality("Sarawak")
        |> CertOwner.set_country("MY")
        |> CertOwner.add_org_unit("X Division")
        |> CertOwner.add_org_unit("Enanble")
        |> CertOwner.set_public_key(KeypairManager.public_key(rskeypair))

      {:der, {:ap_java_crypto, root_cert}} =
        CertProfile.self_sign_issuer_cert_config(
          KeypairManager.private_key(skeypair, :exccrypto_external_signer)
        )
        |> CertProfile.set_signing_hash(:sha384)
        |> CertProfile.set_validity_period(:now, {10, :year})
        |> CertProfile.set_crl_dist_point("https://random.com/crl.crl")
        |> CertProfile.set_ocsp_url(["https://random-2.com/ocsp", "https://random3.com/ocsp"])
        |> CertProfile.set_issuer_url("https://random-2.com/issuer.crt")
        |> CertProfile.set_timestamping_url("https://random-2.com/dts")
        |> CertProfile.set_ca_repository_url("https://random-2.com/repos")
        |> CertGenerator.generate(root_co)

      IO.inspect(root_cert)

      File.write!("slh_dsa_root.cer", root_cert)

      assert {:ok, nskeystore} =
               KeystoreManager.update_keystore_auth_token(skeystore, "p@ssw0rd", "p@ssw0rd2")

      assert {:error, :password_incorrect} =
               KeystoreManager.keystore_to_keypair(nskeystore, "p@ssw0rd")

      assert {:ok, nkeypair} =
               KeystoreManager.keystore_to_keypair(nskeystore, "p@ssw0rd2")

      IO.inspect(nkeypair)
    end)
  end
end
