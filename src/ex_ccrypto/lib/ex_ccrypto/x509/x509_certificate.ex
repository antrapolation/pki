defmodule ExCcrypto.X509.X509Certificate do
  alias ExCcrypto.Asymkey.RSA.RSAPublicKey
  alias ExCcrypto.X509.CertOwner
  alias ExCcrypto.Digest.DigestContextBuilder
  alias ExCcrypto.Asymkey.Ecc.EccPublicKey
  alias ExCcrypto.Asymkey.KeyEncoding
  alias ExCcrypto.Digest
  alias ExCcrypto.X509.X509Certificate
  require X509.ASN1

  require Logger

  @type cert_pack ::
          {:der, binary()} | {:pem, String.t()} | {:native, X509.ASN1.otp_certificate()}

  ## special case for ApJavaCrypto generated certificate
  # def to_pem({:der, {:ap_java_crypto, _cert}} = cert) do
  #  ApJavaCrypto.x509_to_pem(cert)
  # end

  def to_pem({:native, cert}) do
    {:pem, X509.Certificate.to_pem(cert)}
  end

  def to_pem({:der, cert}) do
    {:pem, X509.Certificate.to_pem(X509.Certificate.from_der!(cert))}
  end

  def to_pem({:pem, _c} = cert) do
    cert
  end

  def to_der({:native, cert}) do
    {:der, X509.Certificate.to_der(cert)}
  end

  # def to_der({:pem, {:ap_java_crypto, _cert}} = cert) do
  #  ApJavaCrypto.x509_to_der(cert)
  # end

  def to_der({:pem, cert}) do
    {:der, X509.Certificate.to_der(X509.Certificate.from_pem!(cert))}
  end

  def to_der({:der, _c} = cert) do
    cert
  end

  def to_native(X509.ASN1.otp_certificate() = cert) do
    {:native, cert}
  end

  def to_native({:native, _c} = cert) do
    cert
  end

  def to_native({:pem, cert}) do
    {:native, X509.Certificate.from_pem!(cert)}
  end

  def to_native({:der, cert}) do
    {:native, X509.Certificate.from_der!(cert)}
  end

  def to_native!(X509.ASN1.otp_certificate() = cert), do: cert

  def to_native!({:native, cert}) do
    cert
  end

  def to_native!({:pem, _} = cert) do
    {:native, ncert} = to_native(cert)
    ncert
  end

  def to_native!({:der, _} = cert) do
    {:native, ncert} = to_native(cert)
    ncert
  end

  def compare(cert1, cert2) do
    ncert1 = to_native!(cert1)
    ncert2 = to_native!(cert2)
    ncert1 == ncert2
  end

  @spec is_issued_by?(any(), any()) :: boolean()
  def is_issued_by?(
        {:native, X509.ASN1.otp_certificate() = subject},
        {:native, X509.ASN1.otp_certificate() = issuer}
      ),
      do: is_issued_by?(subject, issuer)

  def is_issued_by?(
        X509.ASN1.otp_certificate() = subject,
        {:native, X509.ASN1.otp_certificate() = issuer}
      ),
      do: is_issued_by?(subject, issuer)

  def is_issued_by?(
        {:native, X509.ASN1.otp_certificate() = subject},
        X509.ASN1.otp_certificate() = issuer
      ),
      do: is_issued_by?(subject, issuer)

  def is_issued_by?(X509.ASN1.otp_certificate() = subject, X509.ASN1.otp_certificate() = issuer),
    do: :public_key.pkix_is_issuer(subject, issuer)

  # def is_issued_by?(
  #      {:der, {:ap_java_crypto, subject}},
  #      {:der, {:ap_java_crypto, issuer}}
  #    ) do
  #  with {:ok, true} <- ApJavaCrypto.cert_verify_issuer({:der, subject}, {:der, issuer}) do
  #    true
  #  else
  #    _ -> false
  #  end
  # end

  @spec verify_certificate(any(), any()) :: boolean()
  def verify_certificate(
        {:native, X509.ASN1.otp_certificate() = subject},
        {:native, X509.ASN1.otp_certificate() = issuer}
      ),
      do: verify_certificate(subject, issuer)

  def verify_certificate(
        X509.ASN1.otp_certificate() = subject,
        {:native, X509.ASN1.otp_certificate() = issuer}
      ),
      do: verify_certificate(subject, issuer)

  def verify_certificate(
        {:native, X509.ASN1.otp_certificate() = subject},
        X509.ASN1.otp_certificate() = issuer
      ),
      do: verify_certificate(subject, issuer)

  def verify_certificate(
        X509.ASN1.otp_certificate() = subject,
        X509.ASN1.otp_certificate() = issuer
      ) do
    subject
    |> X509.Certificate.to_der()
    |> :public_key.pkix_verify(X509.Certificate.public_key(issuer))
  end

  # def verify_certificate({:der, {:ap_java_crypto, subj}}, {:der, {:ap_java_crypto, iss}}) do
  #  with {:ok, true} <- ApJavaCrypto.verify_cert_validity({:der, subj}, :now),
  #       {:ok, true} <- ApJavaCrypto.cert_verify_issuer({:der, subj}, {:der, iss}) do
  #    true
  #  else
  #    _ -> false
  #  end
  # end

  def cert_already_valid?(cert, ref \\ DateTime.utc_now())

  def cert_already_valid?(X509.ASN1.otp_certificate() = cert, ref) do
    {:Validity, before, _} = X509.Certificate.validity(cert)
    before_dt = X509.DateTime.to_datetime(before)
    DateTime.after?(before_dt, ref)
  end

  # def cert_already_valid?({:der, {:ap_java_crypto, cert}}, ref) do
  #  with {:ok, true} <- ApJavaCrypto.verify_cert_validity({:der, cert}, ref) do
  #    true
  #  else
  #    _ -> false
  #  end
  # end

  def cert_already_expired?(cert, ref \\ DateTime.utc_now())

  def cert_already_expired?(X509.ASN1.otp_certificate() = cert, ref) do
    {:Validity, _, aft} = X509.Certificate.validity(cert)
    aft_dt = X509.DateTime.to_datetime(aft)
    DateTime.before?(aft_dt, ref)
  end

  # def cert_already_expired?({:der, {:ap_java_crypto, cert}}, ref) do
  #  with {:ok, true} <- ApJavaCrypto.verify_cert_validity({:der, cert}, ref) do
  #    true
  #  else
  #    _ -> false
  #  end
  # end

  def cert_validity_check(cert, ref \\ DateTime.utc_now()) do
    case cert_already_valid?(cert, ref) do
      true ->
        case cert_already_expired?(cert, ref) do
          true ->
            {:error, :certificate_already_expired}

          false ->
            {:ok, :certificate_datetime_still_valid}
        end

      false ->
        {:error, :certificate_not_yet_valid}
    end
  end

  def subject_as_string(X509.ASN1.otp_certificate() = cert) do
    # IO.inspect(X509.Certificate.subject(cert))
    X509.RDNSequence.to_string(X509.Certificate.subject(cert))
    # X509.Certificate.subject(cert)
  end

  def subject_as_list(X509.ASN1.otp_certificate() = cert) do
    extract_rdnseq(X509.Certificate.subject(cert))
  end

  def subject_org(X509.ASN1.otp_certificate() = cert) do
    subj_dn = subject_as_list(cert)

    case subj_dn[:organizationName] do
      [name] -> name
      nil -> ""
    end
  end

  def subject_org(cert) when is_tuple(cert),
    do: X509Certificate.issuer_org(X509Certificate.to_native!(cert))

  def issuer_as_string(X509.ASN1.otp_certificate() = cert) do
    X509.RDNSequence.to_string(X509.Certificate.issuer(cert))
  end

  def issuer_as_list(X509.ASN1.otp_certificate() = cert) do
    extract_rdnseq(X509.Certificate.issuer(cert))
  end

  def issuer_org(X509.ASN1.otp_certificate() = cert) do
    iss_dn = issuer_as_list(cert)

    case iss_dn[:organizationName] do
      [name] -> name
      nil -> ""
    end
  end

  def issuer_org(cert) when is_tuple(cert),
    do: X509Certificate.issuer_org(X509Certificate.to_native!(cert))

  def public_key(X509.ASN1.otp_certificate() = cert) do
    X509.Certificate.public_key(cert)
  end

  def public_key({:native, X509.ASN1.otp_certificate() = cert}) do
    X509.Certificate.public_key(cert)
  end

  def public_key_id({:der, _} = cert) do
    public_key_id(X509Certificate.to_native!(cert))
  end

  def public_key_id({:native, cert}) do
    public_key_id(cert)
  end

  def public_key_id(X509.ASN1.otp_certificate() = cert) do
    generate_public_key_id(X509.Certificate.public_key(cert))
  end

  def generate_public_key_id({:native, X509.ASN1.otp_certificate() = cert}) do
    generate_public_key_id(X509.Certificate.public_key(cert))
  end

  def generate_public_key_id(X509.ASN1.otp_certificate() = cert) do
    generate_public_key_id(X509.Certificate.public_key(cert))
  end

  def generate_public_key_id({{:ECPoint, _}, {:namedCurve, _}} = pubKey) do
    {:ok, pubKeyDer} =
      KeyEncoding.encode(%EccPublicKey{format: :native, value: pubKey}, :der)

    {:ok, %{digested: dgstVal} = _dgst} =
      DigestContextBuilder.digest_context(:sha3_256)
      |> Digest.digest_init()
      |> Digest.digest_update(pubKeyDer)
      |> Digest.digest_final()

    dgstVal
  end

  def generate_public_key_id({:RSAPublicKey, _, _} = pubKey) do
    {:ok, pubKeyDer} =
      KeyEncoding.encode(%RSAPublicKey{format: :native, value: pubKey}, :der)

    {:ok, %{digested: dgstVal} = _dgst} =
      DigestContextBuilder.digest_context(:sha3_256)
      |> Digest.digest_init()
      |> Digest.digest_update(pubKeyDer)
      |> Digest.digest_final()

    dgstVal
  end

  defp extract_rdnseq({:rdnSequence, _} = seq) do
    fields = [
      "commonName",
      "organizationName",
      "countryName",
      "stateOrProvinceName",
      "localityName",
      "surname",
      "givenName",
      "serialNumber",
      "title",
      "name",
      "initials",
      "organizationalUnitName",
      "emailAddress",
      "domainComponent",
      "dnQualifier",
      "pseudonym",
      "generationQualifier",
      "anotherName"
    ]

    Enum.into(fields, %{}, fn key ->
      v = X509.RDNSequence.get_attr(seq, key)

      {String.to_existing_atom(key), v}
    end)
    |> Map.reject(fn {_key, val} ->
      length(val) == 0
    end)
  end

  def serial_number(X509.ASN1.otp_certificate() = cert) do
    X509.Certificate.serial(cert)
  end

  def is_issuer?({:native, cert}) do
    is_issuer?(cert)
  end

  def is_issuer?({_, _} = ccert) do
    is_issuer?(X509Certificate.to_native(ccert))
  end

  def is_issuer?(X509.ASN1.otp_certificate() = cert) do
    {:Extension, _, _, {:BasicConstraints, val, _level}} =
      X509.Certificate.extension(cert, :basic_constraints)

    val == true
  end

  def to_cert_owner(X509.ASN1.otp_certificate() = cert) do
    parse_extensions(cert, %CertOwner{})
    # %CertOwner{cert_owner | public_key: X509.CSR.public_key(csr)}
  end

  defp parse_extensions(cert, cert_owner) do
    # exts = X509.CSR.extension_request(csr)
    exts = X509.Certificate.extensions(cert)

    Enum.reduce(exts, cert_owner, fn {:Extension, oid, _critical, ext} = full, co ->
      Logger.debug("full ext : #{inspect(full)}")

      case oid do
        {2, 5, 29, 17} ->
          # iPAddress
          {_type, vval} = List.first(ext)

          ipv =
            for <<f::8, s::8, t::8, ff::8 <- vval>> do
              {f, s, t, ff}
            end
            |> List.first()
            |> :inet.ntoa()
            |> to_string

          Logger.debug("found IP address : #{inspect(ipv)}")
          CertOwner.add_ip_address(co, to_string(ipv))

        {2, 5, 29, 15} ->
          # keyUsage
          # Example
          # [:digitalSignature, :nonRepudiation, :keyAgreement]
          co

        {2, 5, 29, 19} ->
          # BasicConstraints
          # Example
          # {:BasicConstraints, false, :asn1_NOVALUE}
          co

        {2, 5, 29, 35} ->
          # authorityKeyID
          # Example:
          # {:AuthorityKeyIdentifier, <<170, 5, 171, 201, 124, 213, 192, 64, 184, 140, 4, 124, 84, 20, 143, 216, 178, 235, 106, 48>>, :asn1_NOVALUE, :asn1_NOVALUE}
          co

        oid ->
          Logger.debug("OID : #{inspect(oid)} / #{inspect(ext)}")
          co
      end

      # case ext do
      #  x when is_tuple(x) ->
      #    co

      #  x when is_list(x) ->
      #    Logger.debug("found list : #{inspect(x)}")
      #    {type, vval} = List.first(x)

      #    case type do
      #      :rfc822Name ->
      #        CertOwner.add_email(co, to_string(vval))

      #      :dNSName ->
      #        CertOwner.add_dns_name(co, to_string(vval))

      #      :uniformResourceIdentifier ->
      #        CertOwner.add_url(co, to_string(vval))

      #      :iPAddress ->
      #        ipv =
      #          for <<f::8, s::8, t::8, ff::8 <- vval>> do
      #            {f, s, t, ff}
      #          end
      #          |> List.first()
      #          |> :inet.ntoa()
      #          |> to_string

      #        Logger.debug("found IP address : #{inspect(ipv)}")
      #        CertOwner.add_ip_address(co, to_string(ipv))

      #      r ->
      #        Logger.debug(" found : #{inspect(r)}")
      #        co
      #    end

      #  res ->
      #    co
      # end
    end)

    # Enum.reduce(exts, cert_owner, fn {:Extension, _, _, val}, co ->
    #  [{type, vval}] = val

    #  case type do
    #    :rfc822Name ->
    #      CertOwner.add_email(co, to_string(vval))

    #    :dNSName ->
    #      CertOwner.add_dns_name(co, to_string(vval))

    #    :uniformResourceIdentifier ->
    #      CertOwner.add_url(co, to_string(vval))

    #    :iPAddress ->
    #      ipv =
    #        for <<f::8, s::8, t::8, ff::8 <- vval>> do
    #          {f, s, t, ff}
    #        end
    #        |> List.first()
    #        |> :inet.ntoa()
    #        |> to_string

    #      CertOwner.add_ip_address(co, to_string(ipv))

    #    r ->
    #      Logger.debug(" found : #{inspect(r)}")
    #      co
    #  end
    # end)
  end
end
