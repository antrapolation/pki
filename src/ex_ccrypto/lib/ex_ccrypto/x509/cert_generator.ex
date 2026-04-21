# Public Struct
defmodule ExCcrypto.X509.CertGenerator do
  require X509.ASN1
  alias ExCcrypto.Asymkey.KeyEncoding
  alias ExCcrypto.X509.X509Certificate
  alias X509.Certificate.Validity
  alias ExCcrypto.X509.CertProfile
  alias X509.Certificate.Extension
  alias ExCcrypto.X509.CSRValidator

  require Logger

  # CertOwner with map reach here
  def generate(_cert_profile, cert_owner)
      when is_map(cert_owner) and not is_map_key(cert_owner, :public_key),
      do: {:error, :owner_public_key_is_not_given}

  def generate(_cert_profile, cert_owner)
      when is_map(cert_owner) and not is_map_key(cert_owner, :public_key),
      do: {:error, :owner_public_key_is_not_given}

  def generate(_cert_profile, %{public_key: pubkey}) when is_nil(pubkey),
    do: {:error, :owner_public_key_is_not_given}

  # root CA via CSR
  def generate(
        %{is_issuer: true, self_sign: true, issuer_key: privkey} = cert_profile,
        X509.ASN1.certification_request() = csr
      ) do
    Logger.debug("Generating Root CA from CSR")

    owner =
      CSRValidator.verify!(csr)
      |> CSRValidator.extract_cert_owner()
      |> verify_cert_owner()

    Logger.debug("Owner struct : #{inspect(owner)}")

    exts =
      owner.ext ++
        cert_profile_extensions(cert_profile, owner)

    Logger.debug("extensions : #{inspect(exts)}")

    rr = CertProfile.verify_validity(cert_profile)

    {:native,
     X509.Certificate.self_signed(KeyEncoding.to_native!(privkey), owner.subject,
       template: :root_ca,
       hash: cert_profile.hash,
       serial: cert_profile.serial,
       validity: Validity.new(rr.cert_validity.not_before, rr.cert_validity.not_after),
       extensions: exts
     )}
  end

  # root CA direct
  def generate(
        %{is_issuer: true, self_sign: true, issuer_key: privkey} = cert_profile,
        cert_owner
      ) do
    Logger.debug("Generating Root CA #{inspect(cert_profile)}")
    owner = verify_cert_owner(cert_owner)

    Logger.debug("cert owner : #{inspect(owner)}")

    exts =
      owner.ext ++
        cert_profile_extensions(cert_profile, cert_owner)

    Logger.debug("extensions : #{inspect(exts)}")

    rr = CertProfile.verify_validity(cert_profile)
    Logger.debug("validity : #{inspect(rr)}")

    Logger.debug("privkey : #{inspect(privkey)}")
    Logger.debug("owner : #{inspect(owner)}")

    {
      :native,
      X509.Certificate.self_signed(KeyEncoding.to_native!(privkey), owner.subject,
        template: :root_ca,
        hash: cert_profile.hash,
        serial: cert_profile.serial,
        validity: Validity.new(rr.cert_validity.not_before, rr.cert_validity.not_after),
        extensions: exts
      )
    }
  end

  # sub CA via CSR
  def generate(
        %{is_issuer: true, self_sign: false, issuer_key: issuer_key} =
          cert_profile,
        X509.ASN1.certification_request()
      )
      when is_nil(issuer_key),
      do: {:error, {:issuer_key_cannot_be_nil_in_issuing_sub_issuer, cert_profile}}

  def generate(
        %{is_issuer: true, self_sign: false, issuer_cert: issuer_cert} =
          cert_profile,
        X509.ASN1.certification_request()
      )
      when is_nil(issuer_cert),
      do: {:error, {:issuer_certificate_cannot_be_nil_in_issuing_sub_issuer, cert_profile}}

  def generate(
        %{is_issuer: true, self_sign: false, issuer_key: issuer_key, issuer_cert: issuer_cert} =
          cert_profile,
        X509.ASN1.certification_request() = csr
      ) do
    Logger.debug("Generating Sub CA from CSR")

    owner =
      CSRValidator.verify!(csr)
      |> CSRValidator.extract_cert_owner()
      |> verify_cert_owner()

    Logger.debug("Sub CA from CSR subject : #{inspect(owner)}")

    exts =
      owner.ext ++
        cert_profile_extensions(cert_profile, owner)

    Logger.debug("extensions : #{inspect(exts)}")

    {:native, iss_cert} = ExCcrypto.X509.X509Certificate.to_native(issuer_cert)

    rr = CertProfile.verify_validity(cert_profile)

    {:native,
     X509.Certificate.new(
       KeyEncoding.to_native!(owner.public_key),
       owner.subject,
       iss_cert,
       KeyEncoding.to_native!(issuer_key),
       template: :root_ca,
       hash: cert_profile.hash,
       serial: cert_profile.serial,
       validity: Validity.new(rr.cert_validity.not_before, rr.cert_validity.not_after),
       extensions: exts
     )}
  end

  # sub CA direct
  def generate(
        %{is_issuer: true, self_sign: false, issuer_key: issuer_key, issuer_cert: issuer_cert} =
          cert_profile,
        cert_owner
      ) do
    Logger.debug("Generating Sub CA")
    owner = verify_cert_owner(cert_owner)

    exts =
      owner.ext ++
        cert_profile_extensions(cert_profile, cert_owner)

    {:native, iss_cert} = ExCcrypto.X509.X509Certificate.to_native(issuer_cert)

    rr =
      CertProfile.verify_validity(cert_profile)
      |> verify_issuer_validity(iss_cert)

    Logger.debug("Sub CA from direct subject : #{inspect(owner)}")

    {:native,
     X509.Certificate.new(
       KeyEncoding.to_native!(owner.public_key),
       owner.subject,
       iss_cert,
       KeyEncoding.to_native!(issuer_key),
       template: :root_ca,
       hash: cert_profile.hash,
       serial: cert_profile.serial,
       validity: Validity.new(rr.cert_validity.not_before, rr.cert_validity.not_after),
       extensions: exts
     )}
  end

  # subscriber from CSR
  def generate(
        %{is_issuer: false, self_sign: false, issuer_key: issuer_key, issuer_cert: issuer_cert} =
          cert_profile,
        X509.ASN1.certification_request() = csr
      ) do
    Logger.debug("Generating Subscriber from CSR")

    owner =
      CSRValidator.verify!(csr)
      |> CSRValidator.extract_cert_owner()
      |> verify_cert_owner()

    exts =
      owner.ext ++
        cert_profile_extensions(cert_profile, owner)

    Logger.debug("extensions : #{inspect(exts)}")

    {:native, iss_cert} = ExCcrypto.X509.X509Certificate.to_native(issuer_cert)

    rr =
      CertProfile.verify_validity(cert_profile)
      |> verify_issuer_validity(iss_cert)

    {:native,
     X509.Certificate.new(
       KeyEncoding.to_native!(owner.public_key),
       owner.subject,
       iss_cert,
       KeyEncoding.to_native!(issuer_key),
       template: :subscriber,
       hash: cert_profile.hash,
       serial: cert_profile.serial,
       validity: Validity.new(rr.cert_validity.not_before, rr.cert_validity.not_after),
       extensions: exts
     )}
  end

  # subscriber for cert_owner
  def generate(
        %{is_issuer: false, self_sign: false, issuer_key: issuer_key, issuer_cert: issuer_cert} =
          cert_profile,
        cert_owner
      ) do
    Logger.debug("Generating Subscriber")
    owner = verify_cert_owner(cert_owner)

    exts =
      owner.ext ++
        cert_profile_extensions(cert_profile, cert_owner)

    {:native, iss_cert} = ExCcrypto.X509.X509Certificate.to_native(issuer_cert)

    rr =
      CertProfile.verify_validity(cert_profile)
      |> verify_issuer_validity(iss_cert)

    {:native,
     X509.Certificate.new(
       KeyEncoding.to_native!(owner.public_key),
       owner.subject,
       iss_cert,
       KeyEncoding.to_native!(issuer_key),
       template: :subscriber,
       hash: cert_profile.hash,
       serial: cert_profile.serial,
       validity: Validity.new(rr.cert_validity.not_before, rr.cert_validity.not_after),
       extensions: exts
     )}
  end

  # self-sign user
  def generate(
        %{is_issuer: false, self_sign: true, issuer_key: privkey} = cert_profile,
        cert_owner
      ) do
    Logger.debug("Generating SelfSign User")

    owner = verify_cert_owner(cert_owner)

    Logger.debug("self sign user cert owner : #{inspect(owner)}")

    exts =
      owner.ext ++
        cert_profile_extensions(cert_profile, cert_owner)

    Logger.debug("self sign user extensions : #{inspect(exts)}")

    rr = CertProfile.verify_validity(cert_profile)
    Logger.debug("validity : #{inspect(rr)}")

    {:native,
     X509.Certificate.self_signed(KeyEncoding.to_native!(privkey), owner.subject,
       template: :subscriber,
       hash: cert_profile.hash,
       serial: cert_profile.serial,
       validity: Validity.new(rr.cert_validity.not_before, rr.cert_validity.not_after),
       extensions: exts
     )}
  end

  # root CA via CSR
  def gen_cert(
        cert_profile,
        X509.ASN1.certification_request() = csr
      ) do
    with {:native, _} = cert <- generate(cert_profile, csr) do
      {:ok, cert}
    end
  end

  # root CA direct
  def gen_cert(
        cert_profile,
        cert_owner
      ) do
    with {:native, _} = cert <- generate(cert_profile, cert_owner) do
      {:ok, cert}
    end
  end

  defp cert_profile_extensions(cert_profile, _cert_owner) do
    {_, exts} =
      construct_key_usage({cert_profile, []})
      |> construct_ext_key_usage()
      |> construct_crl_dist_points()
      |> construct_aia()
      |> construct_basic_constraints()

    exts
  end

  defp construct_basic_constraints(
         {%{is_issuer: issuer, cert_path_length: cert_path_length} = cert_profile, exts}
       )
       when issuer do
    case cert_path_length do
      nil ->
        {cert_profile, exts ++ [basic_constraints: Extension.basic_constraints(true)]}

      pathLen ->
        {cert_profile, exts ++ [basic_constraints: Extension.basic_constraints(true, pathLen)]}
    end

    # {cert_profile,
    # exts ++ [basic_constraints: Extension.basic_constraints(true, cert_path_length)]}
  end

  defp construct_basic_constraints({%{is_issuer: issuer} = cert_profile, exts})
       when not issuer do
    # {cert_profile, exts ++ [basic_constraints: Extension.basic_constraints(false)]}
    {cert_profile, exts}
  end

  defp construct_key_usage({cert_profile, exts}) do
    case cert_profile.key_usage do
      x when x in [nil, []] ->
        {cert_profile, exts}

      _ ->
        ku =
          Enum.map(cert_profile.key_usage, fn u ->
            case u do
              :digital_signature -> :digitalSignature
              :non_repudiation -> :nonRepudiation
              :key_encipherment -> :keyEncipherment
              :data_encipherment -> :dataEncipherment
              :key_agreement -> :keyAgreement
              :key_cert_sign -> :keyCertSign
              :crl_sign -> :cRLSign
              :encipher_only -> :encipherOnly
              :decipher_only -> :decipherOnly
            end
          end)

        {cert_profile, exts ++ [key_usage: Extension.key_usage(ku)]}
    end
  end

  defp construct_ext_key_usage({cert_profile, exts}) do
    case cert_profile.ext_key_usage do
      x when x in [nil, []] ->
        {cert_profile, exts}

      _ ->
        eku =
          Enum.map(cert_profile.ext_key_usage, fn eu ->
            case eu do
              :all_purpose -> :any
              :server_auth -> :serverAuth
              :client_auth -> :clientAuth
              :code_signing -> :codeSigning
              :email_protection -> :emailProtection
              :timestamping -> :timeStamping
              :ocsp_signing -> :ocspSigning
            end
          end)

        {cert_profile, exts ++ [key_usage: Extension.ext_key_usage(eku)]}
    end
  end

  defp construct_crl_dist_points({cert_profile, exts}) do
    case cert_profile.crl_dist_point do
      x when x in [nil, []] ->
        {cert_profile, exts}

      _ ->
        {cert_profile,
         exts ++
           [
             crl_distribution_point:
               Extension.crl_distribution_points(cert_profile.crl_dist_point)
           ]}
    end
  end

  defp construct_aia({cert_profile, exts}) do
    # Logger.debug("ocsp url : #{inspect(cert_profile.ocsp_url)}")

    aia =
      [] ++
        Enum.map(cert_profile.ocsp_url, fn u ->
          {:ocsp, u}
        end) ++
        Enum.map(cert_profile.issuer_url, fn u ->
          {:ca_issuers, u}
        end) ++
        Enum.map(cert_profile.timestamping_url, fn u ->
          {:time_stamping, u}
        end) ++
        Enum.map(cert_profile.ca_repository_url, fn u ->
          {:ca_repository, u}
        end)

    # Logger.debug("aia : #{inspect(aia)}")

    case aia do
      [] ->
        {cert_profile, exts}

      _ ->
        {cert_profile,
         exts ++
           [
             authority_information_access: Extension.authority_info_access(aia)
           ]}
    end
  end

  # defp build_subject(cert_owner, acc \\ [])

  # defp build_subject(%{name: nil} = _cert_owner, acc), do: acc
  # defp build_subject(%{name: ""} = _cert_owner, acc), do: acc

  # defp build_subject(%{name: name} = _cert_owner, acc) do
  #  ["CN=#{name}" | acc]
  # end

  defp verify_cert_owner(cert_owner) do
    %{
      # name: name,
      # serial: serial,
      # org: org,
      # org_unit: org_unit,
      email: email,
      # country: country,
      # state_locality: state_locality,
      ip_address: ip_addr,
      dns_name: dns_name,
      uri: uri,
      public_key: pubkey
    } = cert_owner

    # f =
    #  for em <- email do
    #    "emailAddress=#{em}"
    #  end ++ f

    ext_req =
      for em <- email do
        # otherName, rfc822Name, dNSName, x400Address, directoryName, 
        # ediPartyName, uniformResourceIdentifier, iPAddress, registeredID
        {:subject_alt_name, X509.Certificate.Extension.subject_alt_name(rfc822Name: em)}
      end ++
        for dns <- dns_name do
          {:subject_alt_name, X509.Certificate.Extension.subject_alt_name(dNSName: dns)}
        end ++
        for uri_value <- uri do
          {:subject_alt_name,
           X509.Certificate.Extension.subject_alt_name(uniformResourceIdentifier: uri_value)}
        end ++
        for ip <- ip_addr do
          {:ok, ip_value} = IP.from_string(ip)

          {:subject_alt_name,
           X509.Certificate.Extension.subject_alt_name(iPAddress: Tuple.to_list(ip_value))}
        end

    # %{subject: Enum.join(Enum.reverse(f), "/"), ext: ext_req, public_key: pubkey}
    %{subject: CertProfile.build_subject(cert_owner), ext: ext_req, public_key: pubkey}
  end

  defp verify_issuer_validity(
         config,
         issuer_cert
       )

  defp verify_issuer_validity(config, {:native, issuer_cert}) do
    verify_issuer_validity(config, issuer_cert)
  end

  defp verify_issuer_validity(config, {:pem, issuer_cert}) do
    verify_issuer_validity(config, X509Certificate.to_native(issuer_cert))
  end

  defp verify_issuer_validity(config, {:der, issuer_cert}) do
    verify_issuer_validity(config, X509Certificate.to_native(issuer_cert))
  end

  defp verify_issuer_validity(
         %{
           issued_cert_min_validity_gap: _gap,
           cert_validity: %{not_before: tbs_not_before, not_after: _tbs_not_after}
         } = config,
         issuer_cert
       ) do
    {:Validity, iss_not_before, iss_not_after} = X509.Certificate.validity(issuer_cert)
    inb = X509.DateTime.to_datetime(iss_not_before)
    ina = X509.DateTime.to_datetime(iss_not_after)

    config =
      with 1 <- Timex.compare(inb, tbs_not_before) do
        %{config | cert_validity: %{config.cert_validity | not_before: inb}}
      else
        _ -> config
      end

    Logger.debug("issuer not_after : #{inspect(ina)}")
    check_issuer_end_date_with_cutoff(config, ina)
  end

  defp check_issuer_end_date_with_cutoff(
         %{
           issued_cert_min_validity_gap: {val, :year},
           cert_validity: %{not_after: tbs_not_after}
         } = config,
         issuer_not_after
       ) do
    Logger.debug("cut off #{val} year before")
    cutoff = Timex.shift(issuer_not_after, years: -1 * val)

    %{
      config
      | cert_validity: %{config.cert_validity | not_after: eval_cutoff(tbs_not_after, cutoff)}
    }
  end

  defp check_issuer_end_date_with_cutoff(
         %{
           issued_cert_min_validity_gap: {val, :month},
           cert_validity: %{not_after: tbs_not_after}
         } = config,
         issuer_not_after
       ) do
    Logger.debug("cut off #{val} month before")
    cutoff = Timex.shift(issuer_not_after, months: -1 * val)

    %{
      config
      | cert_validity: %{config.cert_validity | not_after: eval_cutoff(tbs_not_after, cutoff)}
    }
  end

  defp check_issuer_end_date_with_cutoff(
         %{
           issued_cert_min_validity_gap: {val, :day},
           cert_validity: %{not_after: tbs_not_after}
         } = config,
         issuer_not_after
       ) do
    cutoff = Timex.shift(issuer_not_after, days: -1 * val)

    %{
      config
      | cert_validity: %{config.cert_validity | not_after: eval_cutoff(tbs_not_after, cutoff)}
    }
  end

  defp eval_cutoff(ref, cutoff) do
    Logger.debug("ref : #{inspect(ref)}")
    Logger.debug("cutoff : #{inspect(cutoff)}")

    with -1 <- Timex.compare(cutoff, ref) do
      cutoff
    else
      _ -> ref
    end
  end
end
