# Public API
defmodule ExCcrypto.X509.CSRGenerator do
  # alias ExCcrypto.Asymkey.SlhDsa.SlhDsaKeypair
  # alias ExCcrypto.ContextConfig
  # alias ExCcrypto.Asymkey.SlhDsa.SlhDsaPublicKey
  # alias ExCcrypto.Asymkey.MlDsa.MlDsaPublicKey
  # alias ExCcrypto.Asymkey.KazSign.KazSignPublicKey
  alias ExCcrypto.Asymkey.KeyEncoding
  require X509.ASN1
  require Logger

  @type csr :: X509.ASN1.certification_request()

  def generate(cert_owner, signer, opts \\ [])

  # def generate(%{public_key: %KazSignPublicKey{variant: var} = pubkey} = cert_owner, signer, opts)
  #    when var in [:kaz_sign_128, :kaz_sign_192, :kaz_sign_256] do
  #  cowner = %{cert_owner | public_key: {var, :public_key, pubkey.value}}

  #  # {:ok, {:der, csr}} =
  #  with {:ok, {:der, csr}} <-
  #         ApJavaCrypto.generate_csr(
  #           Map.from_struct(cowner),
  #           {signer.variant, :private_key, signer.value},
  #           opts
  #         ) do
  #    {:der, {:ap_java_crypto, csr}}
  #  end
  # end

  # def generate(%{public_key: %MlDsaPublicKey{variant: var} = pubkey} = cert_owner, signer, opts)
  #    when var in [:ml_dsa_44, :ml_dsa_65, :ml_dsa_87] do
  #  cowner = %{cert_owner | public_key: {var, :public_key, pubkey.value}}

  #  # {:ok, {:der, csr}} =
  #  with {:ok, {:der, csr}} <-
  #         ApJavaCrypto.generate_csr(
  #           Map.from_struct(cowner),
  #           {signer.variant, :private_key, signer.value},
  #           opts
  #         ) do
  #    {:der, {:ap_java_crypto, csr}}
  #  end
  # end

  # def generate(%{public_key: %SlhDsaPublicKey{variant: var} = pubkey} = cert_owner, signer, opts) do
  #  case Enum.member?(ContextConfig.get(%SlhDsaKeypair{}, :supported_variant), var) do
  #    true ->
  #      cowner = %{cert_owner | public_key: {var, :public_key, pubkey.value}}

  #      # {:ok, {:der, csr}} =
  #      with {:ok, {:der, csr}} <-
  #             ApJavaCrypto.generate_csr(
  #               Map.from_struct(cowner),
  #               {signer.variant, :private_key, signer.value},
  #               opts
  #             ) do
  #        {:der, {:ap_java_crypto, csr}}
  #      end

  #    false ->
  #      raise "Unsupported SLH-DSA algorithm #{var}"
  #  end
  # end

  def generate(cert_owner, signer, opts) do
    IO.inspect(cert_owner)

    with {:ok, val} <- verify_cert_owner(cert_owner) do
      Logger.debug("val : #{inspect(val)}")

      Map.put(val, :private_key, signer)
      |> generate_csr(opts)
    end
  end

  def to_pem({:native, csr}) do
    {:pem, X509.CSR.to_pem(csr)}
  end

  def to_pem({:der, {:ap_java_crypto, csr}}) do
    {:pem,
     {:ap_java_crypto,
      "-----BEGIN CERTIFICATE SIGNING REQUEST-----\n#{Base.encode64(csr)}\n-----END CERTIFICATE SIGNING REQUEST-----\n"}}
  end

  def to_native({:pem, csr}) do
    {:native, X509.CSR.from_pem!(csr)}
  end

  def to_native(:der, csr) do
    {:native, X509.CSR.from_der!(csr)}
  end

  def to_der({:native, csr}) do
    {:der, X509.CSR.to_der(csr)}
  end

  def to_der({:pem, {:ap_java_crypto, pem}}) do
    {:der,
     {:ap_java_crypto,
      Base.decode64(
        String.replace(pem, "-----BEGIN CERTIFICATE SIGNING REQUEST-----\n", "")
        |> String.replace("\n-----END CERTIFICATE SIGNING REQUEST-----\n", "")
      )}}
  end

  defp generate_csr(%{private_key: %{callback: _cb}} = csr_info, opts) do
    Logger.debug("csr_info 1 : #{inspect(csr_info)}")

    {
      :native,
      X509.CSR.new(csr_info.private_key, csr_info.subject,
        extension_request: csr_info.ext_req,
        public_key: KeyEncoding.to_native!(csr_info.public_key),
        hash: opts[:hash] || :sha384
      )
    }
  end

  defp generate_csr(csr_info, opts) do
    {
      :native,
      X509.CSR.new(KeyEncoding.to_native!(csr_info.private_key), csr_info.subject,
        extension_request: csr_info.ext_req,
        public_key: KeyEncoding.to_native!(csr_info.public_key),
        hash: opts[:hash] || :sha384
      )
    }
  end

  # defp verify_cert_owner(%{name: name, country: country} = cert_owner) do
  defp verify_cert_owner(%{name: name} = cert_owner) do
    with {:ok, _} <- verify_common_name(name) do
      # {:ok, _} <- verify_country(country) do
      build_cert_owner(cert_owner)
    end
  end

  defp verify_common_name(name) do
    case is_nil(name) or byte_size(name) == 0 do
      true -> {:error, :name_is_required}
      false -> {:ok, name}
    end
  end

  # defp verify_country(country) do
  #  case is_nil(country) or byte_size(country) == 0 do
  #    true -> {:error, :country_is_required}
  #    false -> {:ok, country}
  #  end
  # end

  defp build_cert_owner(cert_owner) do
    %{
      name: name,
      org: org,
      org_unit: org_unit,
      email: email,
      country: country,
      ip_address: ip_addr,
      dns_name: dns_name,
      uri: uri,
      public_key: pubkey
    } = cert_owner

    # Logger.debug("CSR generator : org #{inspect(org)} / #{Cond.is_not_empty?(org)}")

    f =
      [""] ++ ["CN=#{String.trim(name)}"]

    f =
      f ++
        for ou <- org_unit do
          "OU=#{String.trim(ou)}"
        end

    f =
      case is_nil(org) or byte_size(org) == 0 do
        true -> f
        false -> f ++ ["O=#{String.trim(org)}"]
      end

    f =
      case is_nil(country) or byte_size(country) == 0 do
        false -> f ++ ["C=#{String.trim(country)}"]
        true -> f
      end

    # f =
    #  Cond.append_list_if_true(f, not is_nil(org) and byte_size(org) > 0, ["O=#{org}"])
    #  |> Cond.append_list_if_true(not is_nil(country) and byte_size(country) > 0, ["C=#{country}"])

    # f = f ++ ["C=#{country}"]

    # f = ["CN=#{name}" | f]

    # f =
    #  for ou <- org_unit do
    #    "OU=#{ou}"
    #  end ++ f

    # f =
    #  if Cond.is_not_empty?(org) do
    #    ["O=#{org}" | f]
    #  end

    # f = ["O=#{org}" | f]

    # f =
    #  if Cond.is_not_empty?(country) do
    #    ["C=#{country}" | f]
    #  else
    #    raise "Country must not be empty"
    #  end

    # f = ["C=#{country}" | f]

    # f =
    #  for em <- email do
    #    # X509.Certificate.Extension.subject_alt_name(emailAddress: em)
    #    "emailAddress=#{em}"
    #  end ++ f

    ext_req =
      for em <- email do
        # otherName, rfc822Name, dNSName, x400Address, directoryName, 
        # ediPartyName, uniformResourceIdentifier, iPAddress, registeredID
        X509.Certificate.Extension.subject_alt_name(rfc822Name: em)
      end ++
        for dns <- dns_name do
          X509.Certificate.Extension.subject_alt_name(dNSName: dns)
        end ++
        for uri_value <- uri do
          X509.Certificate.Extension.subject_alt_name(uniformResourceIdentifier: uri_value)
        end ++
        for ip <- ip_addr do
          {:ok, ip_value} = IP.from_string(ip)
          X509.Certificate.Extension.subject_alt_name(iPAddress: Tuple.to_list(ip_value))
        end

    {:ok, %{subject: Enum.join(f, "/"), ext_req: ext_req, public_key: pubkey}}
  end
end
