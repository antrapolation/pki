defmodule ExCcryptoIntegrationTest do
  alias ExCcrypto.X509.CertOwner
  alias ExCcrypto.X509.CertProfile
  use ExUnit.Case

  test "Generate KAZ-SIGN keypair and certificate" do
    assert {:ok, priv, pub} = ApJavaCrypto.generate_keypair(:kaz_sign_128)
    assert {:kaz_sign_128, :private_key, privkeybin} = priv
    assert {:kaz_sign_128, :public_key, pubkeybin} = pub

    data = "data for signing"
    assert {:ok, sign} = ApJavaCrypto.sign(data, priv)

    assert {:ok, true} = ApJavaCrypto.verify(data, sign, pub)
    assert {:error, false} = ApJavaCrypto.verify("random data", sign, pub)

    ssOwner =
      %CertOwner{}
      |> CertOwner.set_name("Jack Bauer")
      |> CertOwner.add_org_unit("Unit - Security Innovation")
      |> CertOwner.set_org("Antrapol")
      |> CertOwner.set_country("MY")
      |> CertOwner.add_email("JackBauer@24.com")
      |> CertOwner.add_email("Mila@24.com")
      |> CertOwner.add_dns_name("https://www.24.com")
      |> CertOwner.add_dns_name("https://www.24-series.com")
      |> CertOwner.add_ip_address("121.199.23.11")
      |> CertOwner.add_ip_address("199.233.21.22")
      |> CertOwner.set_public_key(pub)

    ssProf =
      CertProfile.self_sign_issuer_cert_config(priv)
      |> CertProfile.set_crl_dist_point("https://myca.com/crl")
      |> CertProfile.set_ext_key_usage([:client_auth, :email_protection, :code_signing])
      |> CertProfile.set_ca_repository_url("ldaps://myca.com/12345")
      |> CertProfile.set_ocsp_url("https://myca.com/ocsp")
      |> CertProfile.set_issuer_url("https://myca.com/issuer/1234")
      |> CertProfile.set_timestamping_url("https://myca.com/tsa")

    assert {:ok, {:der, cert}} =
             ApJavaCrypto.issue_certificate(
               Map.from_struct(ssOwner),
               Map.from_struct(ssProf)
             )

    File.write!("kaz-sign-128-cert.cer", cert)

    certb64 = Base.encode64(cert)

    File.write!(
      "kaz-sign-128-cert.crt",
      "-----BEGIN CERTIFICATE-----\n#{certb64}\n-----END CERTIFICATE-----\n"
    )

    # sub CA
    assert {:ok, sub_priv, sub_pub} = ApJavaCrypto.generate_keypair(:kaz_sign_128)

    sscaOwner =
      %CertOwner{}
      |> CertOwner.set_name("Chloe")
      |> CertOwner.add_org_unit("Unit - Security Defence")
      |> CertOwner.set_org("Antrapol")
      |> CertOwner.set_country("MY")
      |> CertOwner.add_email("Chloe@24.com")
      |> CertOwner.set_public_key(sub_pub)

    sscaProf =
      CertProfile.issuer_cert_config(priv, {:der, cert})
      |> CertProfile.set_crl_dist_point("https://myca.com/crl")
      |> CertProfile.set_ext_key_usage([:client_auth, :email_protection, :code_signing])
      |> CertProfile.set_ca_repository_url("ldaps://myca.com/12345")
      |> CertProfile.set_ocsp_url("https://myca.com/ocsp")
      |> CertProfile.set_issuer_url("https://myca.com/issuer/1234")
      |> CertProfile.set_timestamping_url("https://myca.com/tsa")

    assert {:ok, {:der, sub_ca_cert}} =
             ApJavaCrypto.issue_certificate(
               Map.from_struct(sscaOwner),
               Map.from_struct(sscaProf)
             )

    File.write!("kaz-sign-128-subca-cert.cer", sub_ca_cert)

    File.write!(
      "kaz-sign-128-subca-cert.crt",
      "-----BEGIN CERTIFICATE-----\n#{Base.encode64(sub_ca_cert)}\n-----END CERTIFICATE-----\n"
    )

    # user
    assert {:ok, user_priv, user_pub} = ApJavaCrypto.generate_keypair(:kaz_sign_128)

    userOwner =
      %CertOwner{}
      |> CertOwner.set_name("Milo")
      |> CertOwner.add_org_unit("Unit - Security Exploration")
      |> CertOwner.set_org("Antrapol")
      |> CertOwner.set_country("MY")
      |> CertOwner.add_email("milo@24.com")
      |> CertOwner.set_public_key(user_pub)

    userProf =
      CertProfile.leaf_cert_config(sub_priv, {:der, sub_ca_cert})
      |> CertProfile.set_crl_dist_point("https://myca.com/crl")
      |> CertProfile.set_ext_key_usage([:client_auth, :email_protection, :code_signing])
      |> CertProfile.set_ca_repository_url("ldaps://myca.com/12345")
      |> CertProfile.set_ocsp_url("https://myca.com/ocsp")
      |> CertProfile.set_issuer_url("https://myca.com/issuer/1234")
      |> CertProfile.set_timestamping_url("https://myca.com/tsa")

    assert {:ok, {:der, user_cert}} =
             ApJavaCrypto.issue_certificate(
               Map.from_struct(userOwner),
               Map.from_struct(userProf)
             )

    File.write!("kaz-sign-128-user-cert.cer", user_cert)

    File.write!(
      "kaz-sign-128-user-cert.crt",
      "-----BEGIN CERTIFICATE-----\n#{Base.encode64(user_cert)}\n-----END CERTIFICATE-----\n"
    )
  end
end
