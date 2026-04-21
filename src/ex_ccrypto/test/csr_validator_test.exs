defmodule CsrValidatorTest do
  alias ExCcrypto.Asymkey.KeyEncoding
  alias ExCcrypto.Asymkey
  alias ExCcrypto.Asymkey.Ecc.EccKeypair
  alias ExCcrypto.X509.CSRValidator
  alias ExCcrypto.X509.CSRGenerator
  alias ExCcrypto.X509.CertOwner
  use ExUnit.Case

  test "load CSR into CertOwner" do
    {:ok, %{private_key: privkey, public_key: pubkey}} =
      %EccKeypair{}
      |> Asymkey.generate()

    co =
      CertOwner.set_name(%CertOwner{}, "CSR Owner")
      |> CertOwner.set_org("Anabel")
      |> CertOwner.set_email("test@test.com")
      |> CertOwner.set_email("dev@test.com")
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

    {:native, csr} = CSRGenerator.generate(co, privkey)

    res = CSRValidator.verify(csr) |> CSRValidator.extract_cert_owner()
    IO.puts("Verified CSR : #{inspect(res)}")
    assert(res.name == co.name)
    assert(res.org == co.org)
    assert(res.country == co.country)
    # assert(res.public_key == KeyEncoding.to_native!(co.public_key))
    assert(res.public_key == co.public_key)
    assert(Enum.sort(res.org_unit) == Enum.sort(co.org_unit))
    assert(Enum.sort(res.email) == Enum.sort(co.email))
    assert(Enum.sort(res.dns_name) == Enum.sort(co.dns_name))
    assert(Enum.sort(res.ip_address) == Enum.sort(co.ip_address))
    assert(Enum.sort(res.uri) == Enum.sort(co.uri))
  end
end
