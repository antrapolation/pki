# Public Struct
defmodule ExCcrypto.X509.CertOwner do
  alias ExCcrypto.X509.CertOwner
  alias ExCcrypto.X509.X509Certificate
  use TypedStruct

  @type public_key_type :: X509.ASN1.ec_point()

  typedstruct do
    field(:name, String.t())
    field(:serial, binary())
    field(:org, String.t())
    field(:org_unit, list(), default: [])
    field(:country, String.t())
    field(:state_locality, String.t())
    field(:public_key, public_key_type())
    field(:email, list(), default: [])
    field(:dns_name, list(), default: [])
    field(:ip_address, list(), default: [])
    field(:uri, list(), default: [])
  end

  require Logger
  # defstruct [
  #  :name,
  #  :serial,
  #  :org,
  #  {:org_unit, []},
  #  :country,
  #  :state_locality,
  #  :public_key,
  #  {:email, []},
  #  {:dns_name, []},
  #  {:ip_address, []},
  #  {:uri, []}
  # ]

  @spec set_name(%ExCcrypto.X509.CertOwner{}, binary()) ::
          %ExCcrypto.X509.CertOwner{}
  def set_name(owner, name) do
    %{owner | name: name}
  end

  @spec set_org(%ExCcrypto.X509.CertOwner{}, binary()) ::
          %ExCcrypto.X509.CertOwner{}

  def set_org(owner, orgname) when byte_size(orgname) == 0, do: owner

  def set_org(owner, orgname) do
    %{owner | org: orgname}
  end

  @deprecated "Use set_serial_in_subject/2 instead"
  @spec set_serial(%ExCcrypto.X509.CertOwner{}, binary()) ::
          %ExCcrypto.X509.CertOwner{}

  def set_serial(owner, serial) when byte_size(serial) == 0, do: owner

  def set_serial(owner, serial) do
    %{owner | serial: serial}
  end

  @spec set_serial_in_subject(%ExCcrypto.X509.CertOwner{}, binary()) ::
          %ExCcrypto.X509.CertOwner{}
  def set_serial_in_subject(owner, serial) when byte_size(serial) == 0, do: owner

  def set_serial_in_subject(owner, serial) do
    %{owner | serial: serial}
  end

  @spec add_org_unit(%ExCcrypto.X509.CertOwner{}, binary() | list()) ::
          %ExCcrypto.X509.CertOwner{}
  def add_org_unit(owner, org_unit) when is_list(org_unit) do
    %{owner | org_unit: owner.org_unit ++ org_unit}
  end

  def add_org_unit(owner, org_unit) when byte_size(org_unit) == 0, do: owner

  def add_org_unit(owner, org_unit) do
    %{owner | org_unit: [org_unit | owner.org_unit]}
  end

  def remove_org_unit(owner, org_unit) when byte_size(org_unit) == 0, do: owner

  def remove_org_unit(owner, org_unit) do
    %{owner | org_unit: Enum.reject(owner.org_unit, fn e -> e == org_unit end)}
  end

  @spec set_public_key(%ExCcrypto.X509.CertOwner{}, public_key_type()) ::
          %ExCcrypto.X509.CertOwner{}
  def set_public_key(owner, pubKey) do
    %{owner | public_key: pubKey}
  end

  @spec set_country(%ExCcrypto.X509.CertOwner{}, binary()) ::
          %ExCcrypto.X509.CertOwner{}
  def set_country(owner, country) when byte_size(country) == 0, do: owner

  def set_country(owner, country) do
    %{owner | country: country}
  end

  def set_state_or_locality(owner, state_or_locality) do
    %{owner | state_locality: state_or_locality}
  end

  def set_email(owner, email) when byte_size(email) == 0, do: owner

  def set_email(owner, email) do
    add_email(owner, email)
  end

  @spec add_email(%ExCcrypto.X509.CertOwner{}, binary() | list()) ::
          %ExCcrypto.X509.CertOwner{}
  def add_email(owner, email) when is_list(email) do
    %{owner | email: owner.email ++ email}
  end

  def add_email(owner, email) when byte_size(email) == 0, do: owner

  def add_email(owner, email) do
    %{owner | email: [email | owner.email]}
  end

  def set_dns_name(owner, dns_name) do
    add_dns_name(owner, dns_name)
  end

  @spec add_dns_name(%ExCcrypto.X509.CertOwner{}, binary() | list()) ::
          %ExCcrypto.X509.CertOwner{}
  def add_dns_name(owner, dns_name) when is_list(dns_name) do
    %{owner | dns_name: owner.dns_name ++ dns_name}
  end

  def add_dns_name(owner, dns_name) when byte_size(dns_name) == 0, do: owner

  def add_dns_name(owner, dns_name) do
    %{owner | dns_name: [dns_name | owner.dns_name]}
  end

  def set_ip_address(owner, ip_addr) when byte_size(ip_addr) == 0, do: owner

  def set_ip_address(owner, ip_addr) do
    add_ip_address(owner, ip_addr)
  end

  @spec add_ip_address(%ExCcrypto.X509.CertOwner{}, binary() | list()) ::
          %ExCcrypto.X509.CertOwner{}
  def add_ip_address(owner, ip_addr) when is_list(ip_addr) do
    %{owner | ip_address: owner.ip_address ++ ip_addr}
  end

  def add_ip_address(owner, ip_addr) when byte_size(ip_addr) == 0, do: owner

  def add_ip_address(owner, ip_addr) do
    %{owner | ip_address: [ip_addr | owner.ip_address]}
  end

  def set_url(owner, url) when byte_size(url) == 0, do: owner

  def set_url(owner, url) do
    add_url(owner, url)
  end

  @spec add_url(%ExCcrypto.X509.CertOwner{}, binary() | list()) ::
          %ExCcrypto.X509.CertOwner{}
  def add_url(owner, url) when is_list(url) do
    %{owner | uri: owner.uri ++ url}
  end

  def add_url(owner, url) when byte_size(url) == 0, do: owner

  def add_url(owner, url) do
    %{owner | uri: [url | owner.uri]}
  end

  def duplicate_subject(owner, {_format, _cert_bin} = cert) do
    duplicate_subject(owner, X509Certificate.to_native!(cert))
  end

  def duplicate_subject(owner, cert) do
    subj = X509Certificate.subject_as_list(cert)
    transfer_subject(owner, subj)
  end

  defp transfer_subject(co, %{commonName: cn} = subj) do
    transfer_subject(
      CertOwner.set_name(co, pick_value(cn)),
      Map.delete(subj, :commonName)
    )
  end

  defp transfer_subject(co, %{organizationName: org} = subj) do
    transfer_subject(
      CertOwner.set_org(co, pick_value(org)),
      Map.delete(subj, :organizationName)
    )
  end

  defp transfer_subject(co, %{countryName: c} = subj) do
    transfer_subject(
      CertOwner.set_org(co, pick_value(c)),
      Map.delete(subj, :countryName)
    )
  end

  defp transfer_subject(co, _subj), do: co

  defp pick_value(sel) do
    case is_list(sel) do
      true ->
        List.first(sel)

      false ->
        sel
    end
  end
end
