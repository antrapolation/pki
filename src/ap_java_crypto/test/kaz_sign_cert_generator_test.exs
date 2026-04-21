defmodule KazSignCertGeneratorTest do
  alias ApJavaCrypto.Keystore
  alias ApJavaCrypto.X509.CSRGenerator
  alias ApJavaCrypto.KazSign.KazSignContext
  alias ApJavaCrypto.X509.X509Certificate
  alias ApJavaCrypto.X509.CertGenerator
  alias ApJavaCrypto.KazSign.KazSignKeypair
  alias ExCcrypto.Asymkey.AsymkeyVerify
  alias ExCcrypto.Asymkey.AsymkeySign
  alias ExCcrypto.ContextConfig
  alias ExCcrypto.Asymkey.AsymkeySignContextBuilder
  alias ExCcrypto.Asymkey.ExternalSigner
  alias ExCcrypto.Asymkey.KeyEncoding
  alias ExCcrypto.Asymkey
  alias ExCcrypto.X509.CertOwner
  alias ExCcrypto.X509.CertProfile

  use ExUnit.Case

  setup do
    {:ok, %{private_key: root_privkey, public_key: root_pubkey}} =
      %KazSignKeypair{}
      |> Asymkey.generate()

    {:ok, %{private_key: subca_privkey, public_key: subca_pubkey}} =
      %KazSignKeypair{}
      |> Asymkey.generate()

    {:ok, %{private_key: subsubca_privkey, public_key: subsubca_pubkey}} =
      %KazSignKeypair{}
      |> Asymkey.generate()

    {:ok, %{private_key: subscriber_privkey, public_key: subscriber_pubkey}} =
      %KazSignKeypair{}
      |> Asymkey.generate()

    {:ok, %{private_key: kaz_128_priv, public_key: kaz_128_pub}} =
      %KazSignKeypair{}
      |> Asymkey.generate()

    {:ok, %{private_key: kaz_192_priv, public_key: kaz_192_pub}} =
      %KazSignKeypair{variant: :kaz_sign_192}
      |> Asymkey.generate()

    {:ok, %{private_key: kaz_256_priv, public_key: kaz_256_pub}} =
      %KazSignKeypair{variant: :kaz_sign_256}
      |> Asymkey.generate()

    %{
      root: %{pubkey: root_pubkey, privkey: root_privkey},
      subca: %{pubkey: subca_pubkey, privkey: subca_privkey},
      subca2: %{pubkey: subsubca_pubkey, privkey: subsubca_privkey},
      subscriber: %{pubkey: subscriber_pubkey, privkey: subscriber_privkey},
      kaz_sign_128: %{pubkey: kaz_128_pub, privkey: kaz_128_priv},
      kaz_sign_192: %{pubkey: kaz_192_pub, privkey: kaz_192_priv},
      kaz_sign_256: %{pubkey: kaz_256_pub, privkey: kaz_256_priv}
    }
  end

  test "KAZ-SIGN generates self-sign issuer X.509 certificate", ctx do
    Enum.each([:kaz_sign_128, :kaz_sign_192, :kaz_sign_256], fn algo ->
      co =
        %CertOwner{}
        |> CertOwner.set_name("Root Issuer")
        |> CertOwner.set_serial("adf1231414")
        |> CertOwner.set_org("Antrapol")
        |> CertOwner.set_email("root@issuer.com")
        |> CertOwner.set_state_or_locality("Selangor")
        |> CertOwner.set_country("MY")
        |> CertOwner.add_org_unit("X Division")
        |> CertOwner.add_org_unit("Enanble")
        |> CertOwner.add_ip_address("188.23.44.23")
        |> CertOwner.add_ip_address("177.23.34.11")
        |> CertOwner.add_url("https://www.random.com")
        |> CertOwner.add_url("https://www.random-2.com")
        |> CertOwner.add_dns_name("random.com")
        |> CertOwner.add_dns_name("random-2.com")
        |> CertOwner.set_public_key(Map.get(ctx, algo).pubkey)

      IO.inspect(co)

      {:der, {:ap_java_crypto, cert}} =
        rcert =
        CertProfile.self_sign_issuer_cert_config(Map.get(ctx, algo).privkey)
        |> CertProfile.set_signing_hash(:sha512)
        |> CertProfile.set_validity_period(:now, {16, :year})
        |> CertProfile.set_crl_dist_point("https://random.com/crl.crl")
        |> CertProfile.set_ocsp_url(["https://random-2.com/ocsp", "https://random3.com/ocsp"])
        |> CertProfile.set_issuer_url("https://random-2.com/issuer.crt")
        |> CertProfile.set_timestamping_url("https://random-2.com/dts")
        |> CertProfile.set_ca_repository_url("https://random-2.com/repos")
        |> CertGenerator.generate(co)

      IO.inspect(cert)
      File.write!("self-sign-issuer-#{algo}.crt", cert)

      assert true = X509Certificate.is_issued_by?(rcert, rcert)
      assert true = X509Certificate.verify_certificate(rcert, rcert)

      data = "this is data to signing"

      {:ok, signRes} =
        %KazSignContext{}
        |> ContextConfig.set(:private_key, Map.get(ctx, algo).privkey)
        |> AsymkeySign.sign_init()
        |> AsymkeySign.sign_update(data)
        |> AsymkeySign.sign_final()

      IO.inspect(signRes)

      {:ok, verRes} =
        AsymkeyVerify.verify_init(signRes, %{verification_key: rcert})
        |> AsymkeyVerify.verify_update(data)
        |> AsymkeyVerify.verify_final(ContextConfig.get(signRes, :signature))

      IO.inspect(verRes)
      assert(verRes.verification_result == true)

      # nc = X509Certificate.to_native!({:pem, cert})
      # IO.puts("nc : #{inspect(nc)}")
      # assert(X509Certificate.subject_as_string(nc) == X509Certificate.issuer_as_string(nc))
      # IO.puts("Subject : #{inspect(X509Certificate.subject_as_string(nc))}")
      # IO.puts("Subject : #{inspect(X509Certificate.subject_as_list(nc))}")
      # IO.puts("Issuer : #{inspect(X509Certificate.issuer_as_string(nc))}")
      # IO.puts("Issuer : #{inspect(X509Certificate.issuer_as_list(nc))}")
      # IO.puts("Public key : #{inspect(X509Certificate.public_key_id(nc))}")
    end)
  end

  test "KAZ-SIGN generates self-sign end user X.509 certificate", ctx do
    Enum.each([:kaz_sign_128, :kaz_sign_192, :kaz_sign_256], fn algo ->
      pubkey = Map.get(ctx, algo).pubkey
      privkey = Map.get(ctx, algo).privkey

      IO.puts("private key : #{inspect(privkey)}")

      co =
        %CertOwner{}
        |> CertOwner.set_name("End User")
        |> CertOwner.set_serial("u12345678")
        |> CertOwner.set_org("Antrapol")
        |> CertOwner.set_email("user@antrapl.com")
        |> CertOwner.set_state_or_locality("Selangor")
        |> CertOwner.set_country("MY")
        |> CertOwner.add_org_unit("X Division")
        |> CertOwner.add_org_unit("Enanble")
        |> CertOwner.add_ip_address("188.23.44.23")
        |> CertOwner.add_ip_address("177.23.34.11")
        |> CertOwner.add_url("https://www.random.com")
        |> CertOwner.add_url("https://www.random-2.com")
        |> CertOwner.add_dns_name("random.com")
        |> CertOwner.add_dns_name("random-2.com")
        |> CertOwner.set_public_key(pubkey)

      {:der, {:ap_java_crypto, cert}} =
        CertProfile.self_sign_leaf_cert_config(privkey)
        |> CertProfile.set_signing_hash(:sha512)
        |> CertProfile.set_validity_period(:now, {2, :year})
        |> CertProfile.set_crl_dist_point("https://random.com/crl.crl")
        |> CertProfile.set_ocsp_url(["https://random-2.com/ocsp", "https://random3.com/ocsp"])
        |> CertProfile.set_issuer_url("https://random-2.com/issuer.crt")
        |> CertProfile.set_timestamping_url("https://random-2.com/dts")
        |> CertProfile.set_ca_repository_url("https://random-2.com/repos")
        |> CertGenerator.generate(co)

      # |> X509Certificate.to_pem()

      IO.inspect(cert)

      File.write!("self-sign-end-user.crt", cert)
      File.write!("self-sign-end-user.pem", KeyEncoding.encode!(privkey, :pem).value)

      # nc = X509Certificate.to_native!({:pem, cert})
      # IO.puts("nc : #{inspect(nc)}")
      # assert(X509Certificate.subject_as_string(nc) == X509Certificate.issuer_as_string(nc))
      # IO.puts("Subject : #{inspect(X509Certificate.subject_as_string(nc))}")
      # IO.puts("Subject : #{inspect(X509Certificate.subject_as_list(nc))}")
      # IO.puts("Issuer : #{inspect(X509Certificate.issuer_as_string(nc))}")
      # IO.puts("Issuer : #{inspect(X509Certificate.issuer_as_list(nc))}")
      # IO.puts("Public key : #{inspect(X509Certificate.public_key_id(nc))}")
    end)
  end

  test "KAZ-SIGN generates self-sign issuer X.509 certificate from CSR", ctx do
    Enum.each([:kaz_sign_128, :kaz_sign_192, :kaz_sign_256], fn algo ->
      co =
        %CertOwner{}
        |> CertOwner.set_name("Root CSR Issuer")
        |> CertOwner.set_org("Antrapol")
        |> CertOwner.set_email("root@issuer.com")
        |> CertOwner.set_state_or_locality("Kuala Lumpur")
        |> CertOwner.set_country("MY")
        |> CertOwner.add_org_unit("X Division")
        |> CertOwner.add_org_unit("Enanble")
        |> CertOwner.add_ip_address("188.23.44.23")
        |> CertOwner.add_ip_address("177.23.34.11")
        |> CertOwner.add_url("https://www.random.com")
        |> CertOwner.add_url("https://www.random-2.com")
        |> CertOwner.add_dns_name("random.com")
        |> CertOwner.add_dns_name("random-2.com")
        |> CertOwner.set_public_key(Map.get(ctx, algo).pubkey)

      {:der, _csr} = csr = CSRGenerator.generate(co, Map.get(ctx, algo).privkey)

      # {:pem, cert} =
      assert {:der, {:ap_java_crypto, cert}} =
               res =
               CertProfile.self_sign_issuer_cert_config(Map.get(ctx, algo).privkey)
               |> CertProfile.set_signing_hash(:sha512)
               # |> CertProfile.set_validity_period({{2024, 6, 1}, {0, 0, 0}}, [{25, :year}, {6, :month}])
               |> CertProfile.set_validity_period(:now, {16, :year})
               |> CertProfile.set_crl_dist_point("https://random.com/crl.crl")
               |> CertProfile.set_ocsp_url([
                 "https://random-2.com/ocsp",
                 "https://random3.com/ocsp"
               ])
               |> CertProfile.set_issuer_url("https://random-2.com/issuer.crt")
               |> CertProfile.set_timestamping_url("https://random-2.com/dts")
               |> CertProfile.set_ca_repository_url("https://random-2.com/repos")
               |> CertGenerator.generate(csr)

      assert {:pem, {:ap_java_crypto, pem}} = X509Certificate.to_pem(res)

      File.write!("self-sign-csr-issuer-#{algo}.crt", cert)
      File.write!("self-sign-csr-issuer-#{algo}.pem", pem)
    end)
  end

  test "KAZ-SIGN generates self-sign issuer, issue sub CA and subscriber X.509 certificate",
       ctx do
    Enum.each([:kaz_sign_128, :kaz_sign_192, :kaz_sign_256], fn algo ->
      Enum.each([:kaz_sign_128, :kaz_sign_192, :kaz_sign_256], fn algo2 ->
        pubkey = Map.get(ctx, algo).pubkey
        privkey = Map.get(ctx, algo).privkey

        subca_pubkey = Map.get(ctx, algo).pubkey
        subca_privkey = Map.get(ctx, algo).privkey

        subscriber_pubkey = Map.get(ctx, algo2).pubkey
        subscriber_privkey = Map.get(ctx, algo2).privkey

        root_co =
          %CertOwner{}
          |> CertOwner.set_name("#{algo} Root Issuer")
          |> CertOwner.set_org("Antrapol")
          |> CertOwner.set_email("root@issuer.com")
          |> CertOwner.set_state_or_locality("Selangor")
          |> CertOwner.set_country("MY")
          |> CertOwner.add_org_unit("X Division")
          |> CertOwner.add_org_unit("Enanble")
          |> CertOwner.set_public_key(pubkey)

        assert {:der, _} =
                 root_cert =
                 CertProfile.self_sign_issuer_cert_config(privkey)
                 |> CertProfile.set_signing_hash(:sha512)
                 |> CertProfile.set_validity_period(:now, {30, :year})
                 |> CertProfile.set_crl_dist_point("https://random.com/crl.crl")
                 |> CertProfile.set_ocsp_url([
                   "https://random-2.com/ocsp",
                   "https://random3.com/ocsp"
                 ])
                 |> CertProfile.set_issuer_url("https://random-2.com/issuer.crt")
                 |> CertProfile.set_timestamping_url("https://random-2.com/dts")
                 |> CertProfile.set_ca_repository_url("https://random-2.com/repos")
                 |> CertGenerator.generate(root_co)

        # {:pem, {:ap_java_crypto, root_cert_pem}} = X509Certificate.to_pem(root_cert)

        # File.write!("self-sign-root-#{algo}-issuer.crt", root_cert_pem)
        # File.write!("self-sign-root-#{algo}-issuer.pem", KeyEncoding.encode!(privkey, :pem).value)
        IO.puts("Root CA : #{inspect(root_cert)}")

        assert true = X509Certificate.is_issued_by?(root_cert, root_cert)
        assert true = X509Certificate.verify_certificate(root_cert, root_cert)

        subca_co =
          %CertOwner{}
          |> CertOwner.set_name("#{algo} Sub CA")
          |> CertOwner.set_org("Antrapol")
          |> CertOwner.set_email("subca2@issuer.com")
          |> CertOwner.set_country("MY")
          |> CertOwner.add_org_unit("X Division")
          |> CertOwner.add_org_unit("Enanble")
          |> CertOwner.set_public_key(subca_pubkey)

        # {:pem, subca_cert} =
        subca_cert =
          CertProfile.issuer_cert_config(privkey, root_cert)
          |> CertProfile.set_signing_hash(:sha512)
          # |> CertProfile.set_validity_period(:now, {10, :year})
          # |> CertProfile.set_validity_period(:now, [{10, :year}, {6, :month}])
          # |> CertProfile.set_validity_period(:now, [{10, :year}, {6, :month}, {20, :day}])
          # |> CertProfile.set_validity_period(:now, [{10, :year}, {6, :month}, {20, :day}, {18, :hour}])
          |> CertProfile.set_validity_period(:now, [
            {10, :year},
            {6, :month},
            {20, :day},
            {18, :hour},
            {45, :min}
          ])
          |> CertProfile.set_crl_dist_point("https://random.com/crl.crl")
          |> CertProfile.set_ocsp_url(["https://random-2.com/ocsp", "https://random3.com/ocsp"])
          |> CertProfile.set_issuer_url("https://random-2.com/issuer.crt")
          |> CertProfile.set_timestamping_url("https://random-2.com/dts")
          |> CertProfile.set_ca_repository_url("https://random-2.com/repos")
          |> CertGenerator.generate(subca_co)

        # |> CertGenerator.to_pem()
        # {:pem, {:ap_java_crypto, subca_cert_pem}} = X509Certificate.to_pem(subca_cert)

        # File.write!("self-sign-subca-2-issuer.crt", subca_cert_pem)

        IO.puts("Sub CA : #{inspect(subca_cert)}")

        assert true = X509Certificate.is_issued_by?(subca_cert, root_cert)
        assert true = X509Certificate.verify_certificate(subca_cert, root_cert)

        # File.write!(
        #  "self-sign-subca-2-issuer.pem",
        #  KeyEncoding.encode!(subca_privkey, :pem).value
        # )

        euser_co =
          %CertOwner{}
          |> CertOwner.set_name("#{algo2} End User")
          |> CertOwner.set_org("Antrapol")
          |> CertOwner.set_email("subca2@issuer.com")
          |> CertOwner.set_country("MY")
          |> CertOwner.add_org_unit("X Division")
          |> CertOwner.add_org_unit("Enanble")
          |> CertOwner.set_public_key(subscriber_pubkey)

        euser_cert =
          CertProfile.leaf_cert_config(subca_privkey, subca_cert)
          |> CertProfile.set_signing_hash(:sha512)
          |> CertProfile.set_validity_period(:now, [
            {1, :year},
            {6, :month},
            {15, :day},
            {12, :hour},
            {30, :min}
          ])
          |> CertProfile.set_crl_dist_point("https://random.com/crl.crl")
          |> CertProfile.set_ocsp_url(["https://random-2.com/ocsp", "https://random3.com/ocsp"])
          |> CertProfile.set_issuer_url("https://random-2.com/issuer.crt")
          |> CertProfile.set_timestamping_url("https://random-2.com/dts")
          |> CertProfile.set_ca_repository_url("https://random-2.com/repos")
          |> CertGenerator.generate(euser_co)

        # |> X509Certificate.to_pem()
        IO.puts("end user cert : #{inspect(euser_cert)}")

        assert true == X509Certificate.is_issued_by?(euser_cert, subca_cert)
        assert X509Certificate.is_issued_by?(euser_cert, root_cert) == false

        assert X509Certificate.verify_certificate(euser_cert, subca_cert) == true
        assert false == X509Certificate.verify_certificate(euser_cert, root_cert)

        # {:native, subcert} = X509Certificate.to_native({:pem, euser_cert})
        # assert X509Certificate.is_issued_by?(subcert, subca_cert)
        # assert X509Certificate.verify_certificate(subcert, subca_cert)

        # File.write!("subscriber.crt", euser_cert)
        # File.write!("subscriber.pem", KeyEncoding.encode!(subscriber_privkey, :pem).value)

        # piggypag to test pkcs12
        assert {:ok, p12} =
                 Keystore.to_pkcs12_keystore(
                   subscriber_privkey,
                   euser_cert,
                   [
                     subca_cert,
                     root_cert
                   ],
                   "password"
                 )

        IO.inspect(p12)

        assert {:ok, rks} = Keystore.load_pkcs12_keystore({:ap_java_crypto, p12}, "password")

        IO.inspect(rks)

        # File.write!("subscriber-ecc.p12", p12)
        # IO.puts("PKCS12 file written to subscriber-ecc.p12")
      end)
    end)
  end
end
