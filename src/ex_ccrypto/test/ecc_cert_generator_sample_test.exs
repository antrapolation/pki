defmodule EccCertGeneratorSampleTest do
  alias Timex.NaiveDateTime
  alias ExCcrypto.Keystore
  alias ExCcrypto.Asymkey.ExternalSigner
  alias ExCcrypto.Asymkey.KeyEncoding
  alias ExCcrypto.Asymkey.Ecc.EccKeypair
  alias ExCcrypto.Asymkey
  alias ExCcrypto.Keypair.Ecc.PrivateKey
  alias ExCcrypto.X509.X509Certificate
  alias ExCcrypto.X509.CertOwner
  alias ExCcrypto.X509.CertGenerator
  alias ExCcrypto.X509.CertProfile
  alias ExCcrypto.X509.CSRGenerator
  use ExUnit.Case

  setup do
    {:ok, %{private_key: root_privkey, public_key: root_pubkey}} =
      %EccKeypair{}
      |> Asymkey.generate()

    {:ok, %{private_key: subca_privkey, public_key: subca_pubkey}} =
      %EccKeypair{}
      |> Asymkey.generate()

    {:ok, %{private_key: subsubca_privkey, public_key: subsubca_pubkey}} =
      %EccKeypair{}
      |> Asymkey.generate()

    {:ok, %{private_key: subscriber_privkey, public_key: subscriber_pubkey}} =
      %EccKeypair{}
      |> Asymkey.generate()

    %{
      root: %{pubkey: root_pubkey, privkey: root_privkey},
      subca: %{pubkey: subca_pubkey, privkey: subca_privkey},
      subca2: %{pubkey: subsubca_pubkey, privkey: subsubca_privkey},
      subscriber: %{pubkey: subscriber_pubkey, privkey: subscriber_privkey}
    }
  end

  @tag skikpped: true
  test "ECC generates self-sign issuer, issue sub CA and subscriber X.509 certificate", %{
    root: %{pubkey: pubkey, privkey: privkey},
    subca: %{pubkey: subca_pubkey, privkey: subca_privkey},
    subscriber: %{
      pubkey: subscriber_pubkey,
      privkey: subscriber_privkey
    }
  } do
    root_co =
      %CertOwner{}
      |> CertOwner.set_name("Antrapolation Technology Root Issuer")
      |> CertOwner.set_org("Antrapolation Technology")
      |> CertOwner.set_state_or_locality("Selangor")
      |> CertOwner.set_country("MY")
      |> CertOwner.set_public_key(pubkey)

    root_cert =
      CertProfile.self_sign_issuer_cert_config(privkey)
      |> CertProfile.set_signing_hash(:sha512)
      |> CertProfile.set_validity_period(
        {{2025, 6, 30}, {0, 0, 0}},
        {10, :year}
      )
      # |> CertProfile.set_crl_dist_point("https://random.com/crl.crl")
      # |> CertProfile.set_ocsp_url(["https://random-2.com/ocsp", "https://random3.com/ocsp"])
      # |> CertProfile.set_issuer_url("https://random-2.com/issuer.crt")
      # |> CertProfile.set_timestamping_url("https://random-2.com/dts")
      # |> CertProfile.set_ca_repository_url("https://random-2.com/repos")
      |> CertGenerator.generate(root_co)

    {:pem, root_cert_pem} = X509Certificate.to_pem(root_cert)

    # to prevent ovetwritting
    session_id = :crypto.strong_rand_bytes(14) |> Base.encode16()

    File.write!("test_artifacts/#{session_id}-root.crt", root_cert_pem)
    File.write!("test_artifacts/#{session_id}-root.pem", KeyEncoding.encode!(privkey, :pem).value)

    assert {:ok, p12} =
             Keystore.to_pkcs12_keystore(
               privkey,
               root_cert,
               [
                 root_cert
               ],
               "@ntr@p0l.c0m"
             )

    File.write!("test_artifacts/#{session_id}-root.p12", p12)
    IO.puts("PKCS12 file written to test_artifacts/#{session_id}-root.p12")

    #
    # Sub Root
    #
    subca_co =
      %CertOwner{}
      |> CertOwner.set_name("Digital Identity Root")
      |> CertOwner.set_org("Antrapolation Technology")
      |> CertOwner.set_country("MY")
      |> CertOwner.add_org_unit("Digital Identity Management")
      |> CertOwner.set_public_key(subca_pubkey)

    subca_cert =
      CertProfile.issuer_cert_config(privkey, root_cert)
      |> CertProfile.set_signing_hash(:sha512)
      # |> CertProfile.set_validity_period(:now, {10, :year})
      # |> CertProfile.set_validity_period(:now, [{10, :year}, {6, :month}])
      # |> CertProfile.set_validity_period(:now, [{10, :year}, {6, :month}, {20, :day}])
      # |> CertProfile.set_validity_period(:now, [{10, :year}, {6, :month}, {20, :day}, {18, :hour}])
      |> CertProfile.set_validity_period(
        {{2025, 5, 30}, {0, 0, 0}},
        [
          {5, :year}
          # {6, :month},
          # {20, :day},
          # {18, :hour},
          # {45, :min}
        ]
      )
      # |> CertProfile.set_crl_dist_point("https://random.com/crl.crl")
      # |> CertProfile.set_ocsp_url(["https://random-2.com/ocsp", "https://random3.com/ocsp"])
      # |> CertProfile.set_issuer_url("https://random-2.com/issuer.crt")
      # |> CertProfile.set_timestamping_url("https://random-2.com/dts")
      # |> CertProfile.set_ca_repository_url("https://random-2.com/repos")
      |> CertGenerator.generate(subca_co)

    # |> CertGenerator.to_pem()
    {:pem, subca_cert_pem} = X509Certificate.to_pem(subca_cert)

    File.write!("test_artifacts/#{session_id}-Digital.ID.Root.crt", subca_cert_pem)

    File.write!(
      "test_artifacts/#{session_id}-Digital.ID.Root.pem",
      KeyEncoding.encode!(subca_privkey, :pem).value
    )

    assert {:ok, p12} =
             Keystore.to_pkcs12_keystore(
               subca_privkey,
               subca_cert,
               [
                 subca_cert,
                 root_cert
               ],
               "@ntr@p0l-d1g1t@l1d"
             )

    File.write!("test_artifacts/#{session_id}-Digital.ID.Root.p12", p12)
    IO.puts("PKCS12 file written to test_artifacts/#{session_id}-Digital.ID.Root.p12")

    euser_co =
      %CertOwner{}
      |> CertOwner.set_name("Chris Liaw Man Cheon")
      |> CertOwner.set_org("Antrapolation Technology")
      |> CertOwner.set_email("chris@antrapol.com")
      |> CertOwner.set_country("MY")
      |> CertOwner.add_org_unit("Chief Executive Officer")
      |> CertOwner.set_public_key(subscriber_pubkey)

    {:pem, euser_cert} =
      subscriber_cert =
      CertProfile.leaf_cert_config(subca_privkey, subca_cert)
      |> CertProfile.set_signing_hash(:sha512)
      |> CertProfile.set_validity_period(
        {{2025, 6, 23}, {0, 0, 0}},
        [
          {3, :year}
          # {6, :month},
          # {15, :day},
          # {12, :hour},
          # {30, :min}
        ]
      )
      # |> CertProfile.set_crl_dist_point("https://random.com/crl.crl")
      # |> CertProfile.set_ocsp_url(["https://random-2.com/ocsp", "https://random3.com/ocsp"])
      # |> CertProfile.set_issuer_url("https://random-2.com/issuer.crt")
      # |> CertProfile.set_timestamping_url("https://random-2.com/dts")
      # |> CertProfile.set_ca_repository_url("https://random-2.com/repos")
      |> CertGenerator.generate(euser_co)
      |> X509Certificate.to_pem()

    {:native, subcert} = X509Certificate.to_native({:pem, euser_cert})
    assert X509Certificate.is_issued_by?(subcert, subca_cert)
    assert X509Certificate.verify_certificate(subcert, subca_cert)

    File.write!("test_artifacts/#{session_id}-subscriber.crt", euser_cert)

    File.write!(
      "test_artifacts/#{session_id}-subscriber.pem",
      KeyEncoding.encode!(subscriber_privkey, :pem).value
    )

    # all certificates must be in native
    assert {:ok, p12} =
             Keystore.to_pkcs12_keystore(
               subscriber_privkey,
               X509Certificate.to_native(subscriber_cert),
               [
                 X509Certificate.to_native(subca_cert),
                 X509Certificate.to_native(root_cert)
               ],
               # "qk@z-ku@nt3r@"
               "@ntr@p0l.c0m"
             )

    File.write!("test_artifacts/#{session_id}-subscriber.p12", p12)
    IO.puts("PKCS12 file written to test_artifacts/#{session_id}-subscriber.p12")
  end
end
