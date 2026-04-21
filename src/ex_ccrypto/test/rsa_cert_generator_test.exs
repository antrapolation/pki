defmodule RSACertGeneratorTest do
  alias ExCcrypto.Asymkey.RSA.RSAKeypair
  alias ExCcrypto.Keystore
  alias ExCcrypto.Asymkey.ExternalSigner
  alias ExCcrypto.Asymkey.KeyEncoding
  alias ExCcrypto.Asymkey
  alias ExCcrypto.X509.X509Certificate
  alias ExCcrypto.X509.CertOwner
  alias ExCcrypto.X509.CertGenerator
  alias ExCcrypto.X509.CertProfile
  alias ExCcrypto.X509.CSRGenerator
  use ExUnit.Case

  setup do
    {:ok, %{private_key: root_privkey, public_key: root_pubkey}} =
      RSAKeypair.new()
      |> Asymkey.generate()

    {:ok, %{private_key: subca_privkey, public_key: subca_pubkey}} =
      RSAKeypair.new()
      |> Asymkey.generate()

    {:ok, %{private_key: subsubca_privkey, public_key: subsubca_pubkey}} =
      RSAKeypair.new()
      |> Asymkey.generate()

    {:ok, %{private_key: subscriber_privkey, public_key: subscriber_pubkey}} =
      RSAKeypair.new()
      |> Asymkey.generate()

    %{
      root: %{pubkey: root_pubkey, privkey: root_privkey},
      subca: %{pubkey: subca_pubkey, privkey: subca_privkey},
      subca2: %{pubkey: subsubca_pubkey, privkey: subsubca_privkey},
      subscriber: %{pubkey: subscriber_pubkey, privkey: subscriber_privkey}
    }
  end

  test "RSA generates self-sign issuer X.509 certificate with multiple hash algo", %{
    root: %{pubkey: pubkey, privkey: privkey}
  } do
    co =
      %CertOwner{}
      |> CertOwner.set_name("Root Issuer for Hashing Algo test")
      |> CertOwner.set_serial("adf1231414")
      |> CertOwner.set_org("Antrapol")
      |> CertOwner.set_state_or_locality("Selangor")
      |> CertOwner.set_country("MY")
      |> CertOwner.add_org_unit("X Division")
      |> CertOwner.add_org_unit("Enanble")
      |> CertOwner.set_public_key(pubkey)

    # sha3 family not supported yet at Erlang 26/Elixir 1.15.7 and X509 library
    Enum.map([:sha256, :sha384, :sha512], fn h ->
      {:native, cert} =
        CertProfile.self_sign_issuer_cert_config(privkey)
        |> CertProfile.set_signing_hash(h)
        |> CertProfile.set_validity_period(:now, {7, :year})
        |> CertProfile.set_crl_dist_point("https://random.com/crl.crl")
        |> CertProfile.set_ocsp_url(["https://random-2.com/ocsp", "https://random3.com/ocsp"])
        |> CertProfile.set_issuer_url("https://random-2.com/issuer.crt")
        |> CertProfile.set_timestamping_url("https://random-2.com/dts")
        |> CertProfile.set_ca_repository_url("https://random-2.com/repos")
        |> CertGenerator.generate(co)

      IO.puts("issuer org : #{is_list(X509Certificate.issuer_org(cert))}")

      # |> X509Certificate.to_pem()

      IO.inspect(cert)
    end)

    # File.write!("test_artifacts/self-sign-issuer.crt", cert)
    # File.write!("test_artifacts/self-sign-issuer.pem", KeyEncoding.encode!(privkey, :pem).value)
  end

  test "RSA generates self-sign issuer X.509 certificate", %{
    root: %{pubkey: pubkey, privkey: privkey}
  } do
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
      |> CertOwner.set_public_key(pubkey)

    {:pem, cert} =
      CertProfile.self_sign_issuer_cert_config(privkey)
      |> CertProfile.set_signing_hash(:sha512)
      |> CertProfile.set_validity_period(:now, {16, :year})
      |> CertProfile.set_crl_dist_point("https://random.com/crl.crl")
      |> CertProfile.set_ocsp_url(["https://random-2.com/ocsp", "https://random3.com/ocsp"])
      |> CertProfile.set_issuer_url("https://random-2.com/issuer.crt")
      |> CertProfile.set_timestamping_url("https://random-2.com/dts")
      |> CertProfile.set_ca_repository_url("https://random-2.com/repos")
      |> CertGenerator.generate(co)
      |> X509Certificate.to_pem()

    File.write!("test_artifacts/self-sign-issuer.crt", cert)
    File.write!("test_artifacts/self-sign-issuer.pem", KeyEncoding.encode!(privkey, :pem).value)

    nc = X509Certificate.to_native!({:pem, cert})
    IO.puts("nc : #{inspect(nc)}")
    assert(X509Certificate.subject_as_string(nc) == X509Certificate.issuer_as_string(nc))
    IO.puts("Subject : #{inspect(X509Certificate.subject_as_string(nc))}")
    IO.puts("Subject : #{inspect(X509Certificate.subject_as_list(nc))}")
    IO.puts("Issuer : #{inspect(X509Certificate.issuer_as_string(nc))}")
    IO.puts("Issuer : #{inspect(X509Certificate.issuer_as_list(nc))}")
    IO.puts("Public key : #{inspect(X509Certificate.public_key_id(nc))}")
  end

  test "RSA generates self-sign end user X.509 certificate", %{
    root: %{pubkey: pubkey, privkey: privkey}
  } do
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

    {:pem, cert} =
      CertProfile.self_sign_leaf_cert_config(privkey)
      |> CertProfile.set_signing_hash(:sha512)
      |> CertProfile.set_validity_period(:now, {2, :year})
      |> CertProfile.set_crl_dist_point("https://random.com/crl.crl")
      |> CertProfile.set_ocsp_url(["https://random-2.com/ocsp", "https://random3.com/ocsp"])
      |> CertProfile.set_issuer_url("https://random-2.com/issuer.crt")
      |> CertProfile.set_timestamping_url("https://random-2.com/dts")
      |> CertProfile.set_ca_repository_url("https://random-2.com/repos")
      |> CertGenerator.generate(co)
      |> X509Certificate.to_pem()

    File.write!("test_artifacts/self-sign-end-user.crt", cert)
    File.write!("test_artifacts/self-sign-end-user.pem", KeyEncoding.encode!(privkey, :pem).value)

    nc = X509Certificate.to_native!({:pem, cert})
    IO.puts("nc : #{inspect(nc)}")
    assert(X509Certificate.subject_as_string(nc) == X509Certificate.issuer_as_string(nc))
    IO.puts("Subject : #{inspect(X509Certificate.subject_as_string(nc))}")
    IO.puts("Subject : #{inspect(X509Certificate.subject_as_list(nc))}")
    IO.puts("Issuer : #{inspect(X509Certificate.issuer_as_string(nc))}")
    IO.puts("Issuer : #{inspect(X509Certificate.issuer_as_list(nc))}")
    IO.puts("Public key : #{inspect(X509Certificate.public_key_id(nc))}")
  end

  test "RSA generates self-sign issuer X.509 certificate from CSR", %{
    root: %{pubkey: pubkey, privkey: privkey}
  } do
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
      |> CertOwner.set_public_key(pubkey)

    {:native, csr} = CSRGenerator.generate(co, privkey)

    {:pem, cert} =
      CertProfile.self_sign_issuer_cert_config(privkey)
      |> CertProfile.set_signing_hash(:sha512)
      |> CertProfile.set_validity_period({{2024, 6, 1}, {0, 0, 0}}, [{25, :year}, {6, :month}])
      |> CertProfile.set_crl_dist_point("https://random.com/crl.crl")
      |> CertProfile.set_ocsp_url(["https://random-2.com/ocsp", "https://random3.com/ocsp"])
      |> CertProfile.set_issuer_url("https://random-2.com/issuer.crt")
      |> CertProfile.set_timestamping_url("https://random-2.com/dts")
      |> CertProfile.set_ca_repository_url("https://random-2.com/repos")
      |> CertGenerator.generate(csr)
      |> X509Certificate.to_pem()

    File.write!("test_artifacts/self-sign-csr-issuer.crt", cert)

    File.write!(
      "test_artifacts/self-sign-csr-issuer.pem",
      KeyEncoding.encode!(privkey, :pem).value
    )
  end

  test "RSA generates self-sign issuer and issue sub CA X.509 certificate", %{
    root: %{pubkey: pubkey, privkey: privkey},
    subca: %{pubkey: subca_pubkey, privkey: subca_privkey}
  } do
    root_co =
      %CertOwner{}
      |> CertOwner.set_name("Root Issuer")
      |> CertOwner.set_org("Antrapol")
      |> CertOwner.set_email("root@issuer.com")
      |> CertOwner.set_state_or_locality("New York")
      |> CertOwner.set_country("US")
      |> CertOwner.add_org_unit("X Division")
      |> CertOwner.add_org_unit("Enanble")
      |> CertOwner.set_public_key(pubkey)

    root_cert =
      CertProfile.self_sign_issuer_cert_config(privkey)
      |> CertProfile.set_signing_hash(:sha512)
      |> CertProfile.set_validity_period(:now, {30, :year})
      |> CertProfile.set_crl_dist_point("https://random.com/crl.crl")
      |> CertProfile.set_ocsp_url(["https://random-2.com/ocsp", "https://random3.com/ocsp"])
      |> CertProfile.set_issuer_url("https://random-2.com/issuer.crt")
      |> CertProfile.set_timestamping_url("https://random-2.com/dts")
      |> CertProfile.set_ca_repository_url("https://random-2.com/repos")
      |> CertGenerator.generate(root_co)

    {:pem, root_cert_pem} = X509Certificate.to_pem(root_cert)

    File.write!("test_artifacts/self-sign-root-issuer.crt", root_cert_pem)

    File.write!(
      "test_artifacts/self-sign-root-issuer.pem",
      KeyEncoding.encode!(privkey, :pem).value
    )

    subca_co =
      %CertOwner{}
      |> CertOwner.set_name("Sub CA")
      |> CertOwner.set_org("Antrapol")
      |> CertOwner.set_email("subca@issuer.com")
      |> CertOwner.set_state_or_locality("Penang")
      |> CertOwner.set_country("MY")
      |> CertOwner.add_org_unit("X Division")
      |> CertOwner.add_org_unit("Enanble")
      |> CertOwner.set_public_key(subca_pubkey)

    {:pem, subca_cert} =
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
      |> X509Certificate.to_pem()

    File.write!("test_artifacts/self-sign-subca-issuer.crt", subca_cert)

    File.write!(
      "test_artifacts/self-sign-subca-issuer.pem",
      KeyEncoding.encode!(subca_privkey, :pem).value
    )

    subca_cert_native = X509Certificate.to_native!({:pem, subca_cert})
    IO.inspect(root_cert)
    IO.puts("")
    IO.inspect(subca_cert_native)

    assert X509Certificate.generate_public_key_id(root_cert) !=
             X509Certificate.generate_public_key_id(
               X509Certificate.to_native!({:pem, subca_cert})
             )
  end

  test "RSA generates self-sign issuer, issue sub CA and subscriber X.509 certificate", %{
    root: %{pubkey: pubkey, privkey: privkey},
    subca: %{pubkey: subca_pubkey, privkey: subca_privkey},
    subscriber: %{
      pubkey: subscriber_pubkey,
      privkey: subscriber_privkey
    }
  } do
    root_co =
      %CertOwner{}
      |> CertOwner.set_name("RSA Root Issuer")
      |> CertOwner.set_org("Antrapol")
      |> CertOwner.set_email("root@issuer.com")
      |> CertOwner.set_state_or_locality("Sarawak")
      |> CertOwner.set_country("MY")
      |> CertOwner.add_org_unit("X Division")
      |> CertOwner.add_org_unit("Enanble")
      |> CertOwner.set_public_key(pubkey)

    root_cert =
      CertProfile.self_sign_issuer_cert_config(privkey)
      |> CertProfile.set_signing_hash(:sha512)
      |> CertProfile.set_validity_period(:now, {30, :year})
      |> CertProfile.set_crl_dist_point("https://random.com/crl.crl")
      |> CertProfile.set_ocsp_url(["https://random-2.com/ocsp", "https://random3.com/ocsp"])
      |> CertProfile.set_issuer_url("https://random-2.com/issuer.crt")
      |> CertProfile.set_timestamping_url("https://random-2.com/dts")
      |> CertProfile.set_ca_repository_url("https://random-2.com/repos")
      |> CertGenerator.generate(root_co)

    {:pem, root_cert_pem} = X509Certificate.to_pem(root_cert)

    File.write!("test_artifacts/self-sign-root-2-issuer.crt", root_cert_pem)

    File.write!(
      "test_artifacts/self-sign-root-2-issuer.pem",
      KeyEncoding.encode!(privkey, :pem).value
    )

    subca_co =
      %CertOwner{}
      |> CertOwner.set_name("RSA Sub CA")
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
    {:pem, subca_cert_pem} = X509Certificate.to_pem(subca_cert)

    File.write!("test_artifacts/self-sign-subca-2-issuer.crt", subca_cert_pem)

    File.write!(
      "test_artifacts/self-sign-subca-2-issuer.pem",
      KeyEncoding.encode!(subca_privkey, :pem).value
    )

    euser_co =
      %CertOwner{}
      |> CertOwner.set_name("RSA End User")
      |> CertOwner.set_org("Antrapol")
      |> CertOwner.set_email("subca2@issuer.com")
      |> CertOwner.set_country("MY")
      |> CertOwner.add_org_unit("X Division")
      |> CertOwner.add_org_unit("Enanble")
      |> CertOwner.set_public_key(subscriber_pubkey)

    {:pem, euser_cert} =
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
      |> X509Certificate.to_pem()

    {:native, subcert} = X509Certificate.to_native({:pem, euser_cert})
    assert X509Certificate.is_issued_by?(subcert, subca_cert)
    assert X509Certificate.verify_certificate(subcert, subca_cert)

    File.write!("test_artifacts/subscriber.crt", euser_cert)

    File.write!(
      "test_artifacts/subscriber.pem",
      KeyEncoding.encode!(subscriber_privkey, :pem).value
    )

    # piggypag to test pkcs12

    # all certificates must be in native

    assert {:ok, p12} =
             Keystore.to_pkcs12_keystore(
               subscriber_privkey,
               X509Certificate.to_native({:pem, euser_cert}),
               [
                 X509Certificate.to_native(subca_cert),
                 X509Certificate.to_native(root_cert)
               ],
               "password"
             )

    File.write!("test_artifacts/subscriber-rsa.p12", p12)
    IO.puts("PKCS12 RSA written to subscriber-rsa.p12")
  end

  test "RSA generates self-sign issuer, issue sub CA and subscriber X.509 certificate all as external signer",
       %{
         root: %{pubkey: pubkey, privkey: privkey},
         subca: %{pubkey: subca_pubkey, privkey: subca_privkey},
         subscriber: %{
           pubkey: subscriber_pubkey,
           privkey: subscriber_privkey
         }
       } do
    root_co =
      %CertOwner{}
      |> CertOwner.set_name("Root 2 Issuer")
      |> CertOwner.set_org("Antrapol")
      |> CertOwner.set_email("root@issuer.com")
      |> CertOwner.set_state_or_locality("Sarawak")
      |> CertOwner.set_country("MY")
      |> CertOwner.add_org_unit("X Division")
      |> CertOwner.add_org_unit("Enanble")
      |> CertOwner.set_public_key(pubkey)

    # simulate call back from external signer
    # could be HSM, SSM or remote?
    extRootSign =
      %ExternalSigner{}
      |> ExternalSigner.set_callback(fn tbs, hash, opts ->
        IO.puts("Callback triggered!")
        :public_key.sign(tbs, hash, KeyEncoding.to_native!(privkey))
      end)
      |> ExternalSigner.set_key_algo(:ecdsa)
      |> ExternalSigner.set_public_key(KeyEncoding.to_native!(pubkey))

    root_cert =
      CertProfile.self_sign_issuer_cert_config(extRootSign)
      |> CertProfile.set_signing_hash(:sha512)
      |> CertProfile.set_validity_period(:now, {30, :year})
      |> CertProfile.set_crl_dist_point("https://random.com/crl.crl")
      |> CertProfile.set_ocsp_url(["https://random-2.com/ocsp", "https://random3.com/ocsp"])
      |> CertProfile.set_issuer_url("https://random-2.com/issuer.crt")
      |> CertProfile.set_timestamping_url("https://random-2.com/dts")
      |> CertProfile.set_ca_repository_url("https://random-2.com/repos")
      |> CertGenerator.generate(root_co)

    {:pem, root_cert_pem} = X509Certificate.to_pem(root_cert)

    File.write!("test_artifacts/self-sign-root-2-issuer.crt", root_cert_pem)

    File.write!(
      "test_artifacts/self-sign-root-2-issuer.pem",
      KeyEncoding.encode!(privkey, :pem).value
    )

    subca_co =
      %CertOwner{}
      |> CertOwner.set_name("Sub 2 CA")
      |> CertOwner.set_org("Antrapol")
      |> CertOwner.set_email("subca2@issuer.com")
      |> CertOwner.set_country("MY")
      |> CertOwner.add_org_unit("X Division")
      |> CertOwner.add_org_unit("Enanble")
      |> CertOwner.set_public_key(subca_pubkey)

    # simulate call back from external signer
    # could be HSM, SSM or remote?
    extSubCaSign =
      %ExternalSigner{}
      |> ExternalSigner.set_callback(fn tbs, hash, opts ->
        IO.puts("Sub CA Callback triggered!")
        :public_key.sign(tbs, hash, KeyEncoding.to_native!(privkey))
      end)
      |> ExternalSigner.set_key_algo(:ecdsa)

    ## {:pem, subca_cert} =
    # CertProfile.issuer_cert_config(privkey, root_cert)
    subca_cert =
      CertProfile.issuer_cert_config(extSubCaSign, root_cert)
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
    {:pem, subca_cert_pem} = X509Certificate.to_pem(subca_cert)

    File.write!("test_artifacts/self-sign-subca-2-issuer.crt", subca_cert_pem)

    File.write!(
      "test_artifacts/self-sign-subca-2-issuer.pem",
      KeyEncoding.encode!(subca_privkey, :pem).value
    )

    # simulate call back from external signer
    # could be HSM, SSM or remote?
    extUserSign =
      %ExternalSigner{}
      |> ExternalSigner.set_callback(fn tbs, hash, opts ->
        IO.puts("User Callback triggered!")
        :public_key.sign(tbs, hash, KeyEncoding.to_native!(subca_privkey))
      end)
      |> ExternalSigner.set_key_algo(:ecdsa)

    euser_co =
      %CertOwner{}
      |> CertOwner.set_name("End User")
      |> CertOwner.set_org("Antrapol")
      |> CertOwner.set_email("subca2@issuer.com")
      |> CertOwner.set_country("MY")
      |> CertOwner.add_org_unit("X Division")
      |> CertOwner.add_org_unit("Enanble")
      |> CertOwner.set_public_key(subscriber_pubkey)

    {:pem, euser_cert} =
      CertProfile.leaf_cert_config(extUserSign, subca_cert)
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
      |> X509Certificate.to_pem()

    File.write!("test_artifacts/subscriber.crt", euser_cert)

    File.write!(
      "test_artifacts/subscriber.pem",
      KeyEncoding.encode!(subscriber_privkey, :pem).value
    )
  end
end
