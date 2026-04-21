defmodule X509CertificateTest do
  alias ExCcrypto.Asymkey.Ecc.EccKeypair
  alias ExCcrypto.Asymkey.RSA.RSAKeypair
  alias ExCcrypto.Asymkey
  alias ExCcrypto.X509.X509Certificate
  alias ExCcrypto.X509.CertOwner
  alias ExCcrypto.X509.CertGenerator
  alias ExCcrypto.X509.CertProfile
  use ExUnit.Case

  setup do
    {:ok, %{private_key: ecc_privkey, public_key: ecc_pubkey}} =
      %EccKeypair{}
      |> Asymkey.generate()

    {:ok, %{private_key: rsa_privkey, public_key: rsa_pubkey}} =
      %RSAKeypair{}
      |> Asymkey.generate()

    %{
      ecc: %{privkey: ecc_privkey, pubkey: ecc_pubkey},
      rsa: %{privkey: rsa_privkey, pubkey: rsa_pubkey}
    }
  end

  describe "to_pem/1" do
    test "converts native certificate to PEM format", %{ecc: %{privkey: privkey, pubkey: pubkey}} do
      {:native, cert} = generate_self_signed_cert(pubkey, privkey, "Test Subject")

      {:pem, pem} = X509Certificate.to_pem({:native, cert})

      assert is_binary(pem)
      assert String.contains?(pem, "-----BEGIN CERTIFICATE-----")
      assert String.contains?(pem, "-----END CERTIFICATE-----")
    end

    test "converts DER certificate to PEM format", %{ecc: %{privkey: privkey, pubkey: pubkey}} do
      {:native, cert} = generate_self_signed_cert(pubkey, privkey, "Test Subject")
      {:der, der} = X509Certificate.to_der({:native, cert})

      {:pem, pem} = X509Certificate.to_pem({:der, der})

      assert is_binary(pem)
      assert String.contains?(pem, "-----BEGIN CERTIFICATE-----")
    end

    test "returns PEM certificate unchanged", %{ecc: %{privkey: privkey, pubkey: pubkey}} do
      {:native, cert} = generate_self_signed_cert(pubkey, privkey, "Test Subject")
      {:pem, pem} = X509Certificate.to_pem({:native, cert})

      result = X509Certificate.to_pem({:pem, pem})

      assert result == {:pem, pem}
    end
  end

  describe "to_der/1" do
    test "converts native certificate to DER format", %{ecc: %{privkey: privkey, pubkey: pubkey}} do
      {:native, cert} = generate_self_signed_cert(pubkey, privkey, "Test Subject")

      {:der, der} = X509Certificate.to_der({:native, cert})

      assert is_binary(der)
    end

    test "converts PEM certificate to DER format", %{ecc: %{privkey: privkey, pubkey: pubkey}} do
      {:native, cert} = generate_self_signed_cert(pubkey, privkey, "Test Subject")
      {:pem, pem} = X509Certificate.to_pem({:native, cert})

      {:der, der} = X509Certificate.to_der({:pem, pem})

      assert is_binary(der)
    end

    test "returns DER certificate unchanged", %{ecc: %{privkey: privkey, pubkey: pubkey}} do
      {:native, cert} = generate_self_signed_cert(pubkey, privkey, "Test Subject")
      {:der, der} = X509Certificate.to_der({:native, cert})

      result = X509Certificate.to_der({:der, der})

      assert result == {:der, der}
    end
  end

  describe "to_native/1" do
    test "wraps native certificate in tuple", %{ecc: %{privkey: privkey, pubkey: pubkey}} do
      {:native, cert} = generate_self_signed_cert(pubkey, privkey, "Test Subject")

      result = X509Certificate.to_native(cert)

      assert result == {:native, cert}
    end

    test "returns native tuple unchanged", %{ecc: %{privkey: privkey, pubkey: pubkey}} do
      {:native, cert} = generate_self_signed_cert(pubkey, privkey, "Test Subject")

      result = X509Certificate.to_native({:native, cert})

      assert result == {:native, cert}
    end

    test "converts PEM to native", %{ecc: %{privkey: privkey, pubkey: pubkey}} do
      {:native, cert} = generate_self_signed_cert(pubkey, privkey, "Test Subject")
      {:pem, pem} = X509Certificate.to_pem({:native, cert})

      {:native, native_cert} = X509Certificate.to_native({:pem, pem})

      assert X509Certificate.compare({:native, cert}, {:native, native_cert})
    end

    test "converts DER to native", %{ecc: %{privkey: privkey, pubkey: pubkey}} do
      {:native, cert} = generate_self_signed_cert(pubkey, privkey, "Test Subject")
      {:der, der} = X509Certificate.to_der({:native, cert})

      {:native, native_cert} = X509Certificate.to_native({:der, der})

      assert X509Certificate.compare({:native, cert}, {:native, native_cert})
    end
  end

  describe "to_native!/1" do
    test "returns native certificate directly", %{ecc: %{privkey: privkey, pubkey: pubkey}} do
      {:native, cert} = generate_self_signed_cert(pubkey, privkey, "Test Subject")

      result = X509Certificate.to_native!(cert)

      assert result == cert
    end

    test "extracts native from tuple", %{ecc: %{privkey: privkey, pubkey: pubkey}} do
      {:native, cert} = generate_self_signed_cert(pubkey, privkey, "Test Subject")

      result = X509Certificate.to_native!({:native, cert})

      assert result == cert
    end

    test "extracts native from PEM tuple", %{ecc: %{privkey: privkey, pubkey: pubkey}} do
      {:native, cert} = generate_self_signed_cert(pubkey, privkey, "Test Subject")
      {:pem, pem} = X509Certificate.to_pem({:native, cert})

      result = X509Certificate.to_native!({:pem, pem})

      assert is_tuple(result)
    end
  end

  describe "compare/2" do
    test "returns true for identical certificates", %{ecc: %{privkey: privkey, pubkey: pubkey}} do
      {:native, cert} = generate_self_signed_cert(pubkey, privkey, "Test Subject")

      assert X509Certificate.compare({:native, cert}, {:native, cert})
    end

    test "returns true for same cert in different formats", %{
      ecc: %{privkey: privkey, pubkey: pubkey}
    } do
      {:native, cert} = generate_self_signed_cert(pubkey, privkey, "Test Subject")
      {:pem, pem} = X509Certificate.to_pem({:native, cert})
      {:der, der} = X509Certificate.to_der({:native, cert})

      assert X509Certificate.compare({:native, cert}, {:pem, pem})
      assert X509Certificate.compare({:native, cert}, {:der, der})
      assert X509Certificate.compare({:pem, pem}, {:der, der})
    end

    test "returns false for different certificates", %{ecc: %{privkey: privkey, pubkey: pubkey}} do
      {:native, cert1} = generate_self_signed_cert(pubkey, privkey, "Subject One")
      {:native, cert2} = generate_self_signed_cert(pubkey, privkey, "Subject Two")

      refute X509Certificate.compare({:native, cert1}, {:native, cert2})
    end
  end

  describe "is_issued_by?/2" do
    test "returns true when subject is issued by issuer", %{
      ecc: %{privkey: privkey, pubkey: pubkey}
    } do
      {:native, root_cert} = generate_self_signed_cert(pubkey, privkey, "Root CA")

      assert X509Certificate.is_issued_by?(root_cert, root_cert)
    end

    test "accepts various format combinations", %{ecc: %{privkey: privkey, pubkey: pubkey}} do
      {:native, cert} = generate_self_signed_cert(pubkey, privkey, "Test Subject")

      assert X509Certificate.is_issued_by?({:native, cert}, {:native, cert})
      assert X509Certificate.is_issued_by?(cert, {:native, cert})
      assert X509Certificate.is_issued_by?({:native, cert}, cert)
      assert X509Certificate.is_issued_by?(cert, cert)
    end
  end

  describe "verify_certificate/2" do
    test "verifies self-signed certificate", %{ecc: %{privkey: privkey, pubkey: pubkey}} do
      {:native, cert} = generate_self_signed_cert(pubkey, privkey, "Test Subject")

      assert X509Certificate.verify_certificate(cert, cert)
    end

    test "accepts various format combinations", %{ecc: %{privkey: privkey, pubkey: pubkey}} do
      {:native, cert} = generate_self_signed_cert(pubkey, privkey, "Test Subject")

      assert X509Certificate.verify_certificate({:native, cert}, {:native, cert})
      assert X509Certificate.verify_certificate(cert, {:native, cert})
      assert X509Certificate.verify_certificate({:native, cert}, cert)
    end
  end

  describe "cert_already_valid?/2" do
    test "returns boolean for certificate validity check", %{
      ecc: %{privkey: privkey, pubkey: pubkey}
    } do
      {:native, cert} = generate_self_signed_cert(pubkey, privkey, "Test Subject")

      result = X509Certificate.cert_already_valid?(cert, DateTime.utc_now())
      assert is_boolean(result)
    end
  end

  describe "cert_already_expired?/2" do
    test "returns boolean for certificate expiry check", %{
      ecc: %{privkey: privkey, pubkey: pubkey}
    } do
      {:native, cert} = generate_self_signed_cert(pubkey, privkey, "Test Subject")

      result = X509Certificate.cert_already_expired?(cert, DateTime.utc_now())
      assert is_boolean(result)
    end
  end

  describe "cert_validity_check/2" do
    test "returns result for certificate validity check", %{
      ecc: %{privkey: privkey, pubkey: pubkey}
    } do
      {:native, cert} = generate_self_signed_cert(pubkey, privkey, "Test Subject")

      result = X509Certificate.cert_validity_check(cert)
      assert match?({:ok, _}, result) or match?({:error, _}, result)
    end
  end

  describe "subject_as_string/1" do
    test "returns subject as string", %{ecc: %{privkey: privkey, pubkey: pubkey}} do
      {:native, cert} = generate_self_signed_cert(pubkey, privkey, "Test Subject Name")

      subject = X509Certificate.subject_as_string(cert)

      assert is_binary(subject)
      assert String.contains?(subject, "Test Subject Name")
    end
  end

  describe "subject_as_list/1" do
    test "returns subject fields as map", %{ecc: %{privkey: privkey, pubkey: pubkey}} do
      co =
        %CertOwner{}
        |> CertOwner.set_name("Test Subject")
        |> CertOwner.set_org("Test Org")
        |> CertOwner.set_country("US")
        |> CertOwner.set_public_key(pubkey)

      {:native, cert} =
        CertProfile.self_sign_issuer_cert_config(privkey)
        |> CertGenerator.generate(co)

      subject = X509Certificate.subject_as_list(cert)

      assert is_map(subject)
      assert subject[:commonName] == ["Test Subject"]
      assert subject[:organizationName] == ["Test Org"]
      assert subject[:countryName] == ["US"]
    end
  end

  describe "subject_org/1" do
    test "returns organization name", %{ecc: %{privkey: privkey, pubkey: pubkey}} do
      co =
        %CertOwner{}
        |> CertOwner.set_name("Test Subject")
        |> CertOwner.set_org("Test Organization")
        |> CertOwner.set_public_key(pubkey)

      {:native, cert} =
        CertProfile.self_sign_issuer_cert_config(privkey)
        |> CertGenerator.generate(co)

      org = X509Certificate.subject_org(cert)

      assert org == "Test Organization"
    end

    test "returns empty string when no organization", %{ecc: %{privkey: privkey, pubkey: pubkey}} do
      co =
        %CertOwner{}
        |> CertOwner.set_name("Test Subject")
        |> CertOwner.set_public_key(pubkey)

      {:native, cert} =
        CertProfile.self_sign_issuer_cert_config(privkey)
        |> CertGenerator.generate(co)

      org = X509Certificate.subject_org(cert)

      assert org == ""
    end
  end

  describe "issuer_as_string/1" do
    test "returns issuer as string", %{ecc: %{privkey: privkey, pubkey: pubkey}} do
      {:native, cert} = generate_self_signed_cert(pubkey, privkey, "Test Issuer")

      issuer = X509Certificate.issuer_as_string(cert)

      assert is_binary(issuer)
      assert String.contains?(issuer, "Test Issuer")
    end
  end

  describe "issuer_as_list/1" do
    test "returns issuer fields as map", %{ecc: %{privkey: privkey, pubkey: pubkey}} do
      co =
        %CertOwner{}
        |> CertOwner.set_name("Test Issuer")
        |> CertOwner.set_org("Issuer Org")
        |> CertOwner.set_country("MY")
        |> CertOwner.set_public_key(pubkey)

      {:native, cert} =
        CertProfile.self_sign_issuer_cert_config(privkey)
        |> CertGenerator.generate(co)

      issuer = X509Certificate.issuer_as_list(cert)

      assert is_map(issuer)
      assert issuer[:commonName] == ["Test Issuer"]
    end
  end

  describe "issuer_org/1" do
    test "returns issuer organization name", %{ecc: %{privkey: privkey, pubkey: pubkey}} do
      co =
        %CertOwner{}
        |> CertOwner.set_name("Test Issuer")
        |> CertOwner.set_org("Issuer Organization")
        |> CertOwner.set_public_key(pubkey)

      {:native, cert} =
        CertProfile.self_sign_issuer_cert_config(privkey)
        |> CertGenerator.generate(co)

      org = X509Certificate.issuer_org(cert)

      assert org == "Issuer Organization"
    end
  end

  describe "public_key/1" do
    test "returns public key from certificate", %{ecc: %{privkey: privkey, pubkey: pubkey}} do
      {:native, cert} = generate_self_signed_cert(pubkey, privkey, "Test Subject")

      pk = X509Certificate.public_key(cert)

      assert is_tuple(pk)
    end

    test "accepts native tuple format", %{ecc: %{privkey: privkey, pubkey: pubkey}} do
      {:native, cert} = generate_self_signed_cert(pubkey, privkey, "Test Subject")

      pk = X509Certificate.public_key({:native, cert})

      assert is_tuple(pk)
    end
  end

  describe "public_key_id/1" do
    test "generates public key ID for ECC certificate", %{
      ecc: %{privkey: privkey, pubkey: pubkey}
    } do
      {:native, cert} = generate_self_signed_cert(pubkey, privkey, "Test Subject")

      pk_id = X509Certificate.public_key_id(cert)

      assert is_binary(pk_id)
      assert byte_size(pk_id) == 32
    end

    test "generates public key ID for RSA certificate", %{
      rsa: %{privkey: privkey, pubkey: pubkey}
    } do
      {:native, cert} = generate_self_signed_cert(pubkey, privkey, "Test Subject")

      pk_id = X509Certificate.public_key_id(cert)

      assert is_binary(pk_id)
      assert byte_size(pk_id) == 32
    end

    test "accepts different formats", %{ecc: %{privkey: privkey, pubkey: pubkey}} do
      {:native, cert} = generate_self_signed_cert(pubkey, privkey, "Test Subject")
      {:der, der} = X509Certificate.to_der({:native, cert})

      pk_id_native = X509Certificate.public_key_id({:native, cert})
      pk_id_der = X509Certificate.public_key_id({:der, der})

      assert pk_id_native == pk_id_der
    end
  end

  describe "generate_public_key_id/1" do
    test "generates consistent ID for same public key", %{ecc: %{pubkey: pubkey}} do
      native_key = ExCcrypto.Asymkey.KeyEncoding.to_native!(pubkey)

      id1 = X509Certificate.generate_public_key_id(native_key)
      id2 = X509Certificate.generate_public_key_id(native_key)

      assert id1 == id2
    end

    test "generates different IDs for different keys", %{
      ecc: %{pubkey: pubkey1},
      rsa: %{pubkey: pubkey2}
    } do
      native_key1 = ExCcrypto.Asymkey.KeyEncoding.to_native!(pubkey1)
      native_key2 = ExCcrypto.Asymkey.KeyEncoding.to_native!(pubkey2)

      id1 = X509Certificate.generate_public_key_id(native_key1)
      id2 = X509Certificate.generate_public_key_id(native_key2)

      refute id1 == id2
    end
  end

  describe "serial_number/1" do
    test "returns certificate serial number", %{ecc: %{privkey: privkey, pubkey: pubkey}} do
      {:native, cert} = generate_self_signed_cert(pubkey, privkey, "Test Subject")

      serial = X509Certificate.serial_number(cert)

      assert is_integer(serial)
    end
  end

  describe "is_issuer?/1" do
    test "returns true for CA certificate", %{ecc: %{privkey: privkey, pubkey: pubkey}} do
      {:native, cert} =
        CertProfile.self_sign_issuer_cert_config(privkey)
        |> CertProfile.set_validity_period(:now, {1, :year})
        |> CertGenerator.generate(
          %CertOwner{}
          |> CertOwner.set_name("Test CA")
          |> CertOwner.set_public_key(pubkey)
        )

      assert X509Certificate.is_issuer?(cert)
    end

    test "returns true for native tuple format", %{ecc: %{privkey: privkey, pubkey: pubkey}} do
      {:native, cert} =
        CertProfile.self_sign_issuer_cert_config(privkey)
        |> CertProfile.set_validity_period(:now, {1, :year})
        |> CertGenerator.generate(
          %CertOwner{}
          |> CertOwner.set_name("Test CA")
          |> CertOwner.set_public_key(pubkey)
        )

      assert X509Certificate.is_issuer?({:native, cert})
    end

    test "returns false for leaf certificate", %{ecc: %{privkey: privkey, pubkey: pubkey}} do
      {:native, cert} =
        CertProfile.self_sign_leaf_cert_config(privkey)
        |> CertProfile.set_validity_period(:now, {1, :year})
        |> CertGenerator.generate(
          %CertOwner{}
          |> CertOwner.set_name("Test Leaf")
          |> CertOwner.set_public_key(pubkey)
        )

      refute X509Certificate.is_issuer?(cert)
    end
  end

  defp generate_self_signed_cert(pubkey, privkey, name) do
    co =
      %CertOwner{}
      |> CertOwner.set_name(name)
      |> CertOwner.set_public_key(pubkey)

    CertProfile.self_sign_issuer_cert_config(privkey)
    |> CertProfile.set_validity_period(:now, {1, :year})
    |> CertGenerator.generate(co)
  end
end
