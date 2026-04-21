# Public API
defmodule ExCcrypto.X509.CSRValidatorException do
  defexception message: "CSR failed to be verified"
end

defmodule ExCcrypto.X509.CSRValidator do
  require X509.ASN1
  alias ExCcrypto.Asymkey.AsymkeyPublicKey
  alias ExCcrypto.X509.CertOwner
  alias ExCcrypto.X509.CSRValidatorException
  require Logger

  @spec verify(X509.CSR.t()) :: X509.CSR.t() | :error
  def verify(csr) do
    case verify_csr(csr) do
      :ok -> csr
      :error -> :error
    end
  end

  def p_verify(csr) do
    case verify_csr(csr) do
      :ok -> {:ok, csr}
      :error -> {:error, :csr_verify_failed}
    end
  end

  @spec verify!(X509.CSR.t()) ::
          X509.CSR.t() | no_return()
  def verify!(csr) do
    case verify_csr(csr) do
      :ok -> csr
      :error -> raise CSRValidatorException
    end
  end

  @spec extract_cert_owner(X509.CSR.t()) :: %ExCcrypto.X509.CertOwner{}
  def extract_cert_owner(csr) do
    Logger.debug("extract cert owner #{inspect(csr)}")

    cert_owner =
      X509.CSR.subject(csr)
      |> parse_subject(%CertOwner{})

    cert_owner = parse_extensions(csr, cert_owner)

    with {:ok, pubkey_obj} <- AsymkeyPublicKey.to_exccrypto_public_key(X509.CSR.public_key(csr)) do
      %CertOwner{
        cert_owner
        | public_key: pubkey_obj
          # | public_key: X509.CSR.public_key(csr)
      }
    end
  end

  @spec parse_subject(X509.RDNSequence.t(), %CertOwner{}) :: %CertOwner{}
  defp parse_subject(csr, _cert_owner) do
    # %CertOwner{
    #  cert_owner
    #  | name: List.first(X509.RDNSequence.get_attr(csr, "commonName")),
    #    org: List.first(X509.RDNSequence.get_attr(csr, "organizationName")),
    #    org_unit: X509.RDNSequence.get_attr(csr, "organizationalUnitName"),
    #    country: List.first(X509.RDNSequence.get_attr(csr, "countryName"))
    # }

    {build_cert_owner, _ccsr} =
      parse_common_name({%CertOwner{}, csr})
      |> parse_org()
      |> parse_org_unit()
      |> parse_country()

    Logger.debug("csr subject : #{inspect(build_cert_owner)}")
    build_cert_owner
  end

  defp parse_common_name({cert_owner, csr}) do
    cn = List.first(X509.RDNSequence.get_attr(csr, "commonName"))
    {%CertOwner{cert_owner | name: cn}, csr}
    # case byte_size(cn) > 0 do
    #  true -> {%CertOwner{cert_owner | name: cn}, csr}
    #  false -> {:error, :csr_common_name_is_empty}
    # end
  end

  defp parse_org({cert_owner, csr}) do
    org = List.first(X509.RDNSequence.get_attr(csr, "organizationName"))
    {%CertOwner{cert_owner | org: org}, csr}
    # case byte_size(org) > 0 do
    #  true -> {%CertOwner{cert_owner | org: org}, csr}
    #  false -> {cert_owner, csr}
    # end
  end

  defp parse_org_unit({cert_owner, csr}) do
    org_unit = X509.RDNSequence.get_attr(csr, "organizationalUnitName")

    case length(org_unit) > 0 do
      true -> {%CertOwner{cert_owner | org_unit: org_unit}, csr}
      false -> {cert_owner, csr}
    end
  end

  defp parse_country({cert_owner, csr}) do
    case X509.RDNSequence.get_attr(csr, "countryName") do
      {:error, _} ->
        Logger.debug("Error getting countryName from CSR. Probably not set")
        {cert_owner, csr}

      _ ->
        case List.first(X509.RDNSequence.get_attr(csr, "countryName")) do
          nil ->
            {cert_owner, csr}

          res ->
            {%CertOwner{cert_owner | country: String.trim(res)}, csr}
        end
    end
  end

  @spec parse_extensions(X509.CSR.t(), %CertOwner{}) :: %CertOwner{}
  defp parse_extensions(csr, cert_owner) do
    exts = X509.CSR.extension_request(csr)

    Enum.reduce(exts, cert_owner, fn {:Extension, _, _, val}, co ->
      [{type, vval}] = val

      case type do
        :rfc822Name ->
          CertOwner.add_email(co, to_string(vval))

        :dNSName ->
          CertOwner.add_dns_name(co, to_string(vval))

        :uniformResourceIdentifier ->
          CertOwner.add_url(co, to_string(vval))

        :iPAddress ->
          ipv =
            for <<f::8, s::8, t::8, ff::8 <- vval>> do
              {f, s, t, ff}
            end
            |> List.first()
            |> :inet.ntoa()
            |> to_string

          CertOwner.add_ip_address(co, to_string(ipv))

        r ->
          Logger.debug(" found : #{inspect(r)}")
          co
      end
    end)
  end

  @spec verify_csr(X509.CSR.t()) :: :ok | :error
  defp verify_csr(csr) do
    with true <- X509.CSR.valid?(csr) do
      :ok
    else
      _ -> :error
    end
  end
end
