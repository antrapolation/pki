defmodule CsrGeneratorTest do
  alias ExCcrypto.Asymkey.ExternalSigner
  alias ExCcrypto.Asymkey.KeyEncoding
  alias ExCcrypto.Asymkey.Ecc.EccKeypair
  alias ExCcrypto.Asymkey
  alias ExCcrypto.X509.CertOwner
  alias ExCcrypto.X509.CSRGenerator
  use ExUnit.Case

  test "CSR Generator software generated keypair" do
    {:ok, %{private_key: privkey, public_key: pubkey}} =
      %EccKeypair{}
      |> Asymkey.generate()

    co =
      CertOwner.set_name(%CertOwner{}, "Test 1")
      |> CertOwner.set_org("Anabel")
      |> CertOwner.set_email("test@test.com")
      |> CertOwner.set_country("MY")
      |> CertOwner.add_org_unit("X Division")
      |> CertOwner.add_org_unit("Enanble")
      |> CertOwner.add_ip_address("188.23.44.23")
      |> CertOwner.add_ip_address("177.23.34.11")
      |> CertOwner.add_url("https://www.ganeray.com")
      |> CertOwner.add_url("https://www.ganeray-2.com")
      |> CertOwner.add_dns_name("ganeray.com")
      |> CertOwner.add_dns_name("ganeray-2.com")
      |> CertOwner.set_public_key(pubkey)

    {:pem, csr} = CSRGenerator.generate(co, privkey) |> CSRGenerator.to_pem()
    IO.inspect(csr)
    File.write!("test_artifacts/test.csr", csr)
  end

  test "CSR Generator with simulation of external generated keypair" do
    {:ok, %{private_key: privkey, public_key: pubkey}} =
      %EccKeypair{}
      |> Asymkey.generate()

    co =
      CertOwner.set_name(%CertOwner{}, "Test CB")
      |> CertOwner.set_org("Anabel CB")
      |> CertOwner.set_email("test@test.com")
      |> CertOwner.set_country("MY")
      |> CertOwner.add_org_unit("X Division")
      |> CertOwner.add_org_unit("Enanble")
      |> CertOwner.add_ip_address("188.23.44.23")
      |> CertOwner.add_url("https://www.ganeray.com")
      |> CertOwner.add_url("https://www.ganeray-cb.com")
      |> CertOwner.add_dns_name("ganeray.com")
      |> CertOwner.add_dns_name("ganeray-cb.com")
      |> CertOwner.set_public_key(pubkey)

    # simulate call back from external signer
    # could be HSM, SSM or remote?
    # cb = fn tbs, hash ->
    #  :public_key.sign(tbs, hash, KeyEncoding.to_native!(privkey))
    # end

    extSign =
      %ExternalSigner{}
      |> ExternalSigner.set_callback(fn tbs, hash, opts ->
        :public_key.sign(tbs, hash, KeyEncoding.to_native!(privkey))
      end)
      |> ExternalSigner.set_key_algo(:ecdsa)

    {:pem, csr} =
      CSRGenerator.generate(co, extSign) |> CSRGenerator.to_pem()

    IO.inspect(csr)
    File.write!("test_artifacts/test-cb.csr", csr)
  end
end
