
java_import java.security.cert.CertificateFactory

java_import java.time.ZonedDateTime
java_import java.time.ZoneOffset

java_import com.antrapol.kaz.jcajce.sign.KAZSIGNKeyGenParameterSpec
java_import com.antrapol.kaz.jcajce.kem.KAZKEMKeyGenParameterSpec

java_import org.bouncycastle.asn1.x509.KeyUsage
java_import org.bouncycastle.asn1.x509.KeyPurposeId

java_import com.ericsson.otp.erlang.OtpErlangAtom
java_import com.ericsson.otp.erlang.OtpErlangLong
java_import com.ericsson.otp.erlang.OtpErlangString

require_relative 'bc_x509'
require_relative 'jcajce_common'

module ApJavaCrypto
  module Engine
    class KAZSIGNEngine

      def self.generate_keypair(
        variant,
        kazProv,
        opts = {}
      )

       benchmark = opts[:benchmark] || false

        kpg = java.security.KeyPairGenerator.get_instance('KAZ-SIGN', kazProv)

        case variant
        when :kaz_sign_128
          kpg.java_send(:initialize, [java.security.spec.AlgorithmParameterSpec], KAZSIGNKeyGenParameterSpec.KAZ_128)
        when :kaz_sign_192
          kpg.java_send(:initialize, [java.security.spec.AlgorithmParameterSpec], KAZSIGNKeyGenParameterSpec.KAZ_192)
        when :kaz_sign_256
          kpg.java_send(:initialize, [java.security.spec.AlgorithmParameterSpec], KAZSIGNKeyGenParameterSpec.KAZ_256)
        else
          raise StandardError, "Invalid KAZ-SIGN variant #{variant}"
        end

        if benchmark
          start = BenchmarkUtils.mark_start
          kp = kpg.generateKeyPair
          [:ok, variant, kp.get_private.get_encoded, kp.get_public.get_encoded, BenchmarkUtils.time_taken(start)]
        else
          kp = kpg.generateKeyPair
          [:ok, variant, kp.get_private.get_encoded, kp.get_public.get_encoded]
        end

      end

      def self.sign(data, privKey, prov, opts = {})

        privKeyObj = com.antrapol.kaz.jcajce.sign.KAZSIGNPrivateKey.from_encoded(privKey.binaryValue)

        JcaJceCommon.sign(data.binaryValue, "KAZ-SIGN", privKeyObj, prov, opts)

      end

      def self.verify(data, signature, pubkey, prov, opts = {})
        pubkeyObj = com.antrapol.kaz.jcajce.sign.KAZSIGNPublicKey.from_encoded(pubkey.binaryValue)

        JcaJceCommon.verify(data.binaryValue, "KAZ-SIGN", signature.binaryValue, pubkeyObj, prov, opts)

      end

      def self.verify_with_cert(data, signature, cert, prov, opts = {})
        
        puts "Verify via X509 Certificate"

        certObj = BCX509.to_java_cert(cert)
        pubkeyObj = certObj.get_public_key

        JcaJceCommon.verify(data.binaryValue, "KAZ-SIGN", signature.binaryValue, pubkeyObj, prov, opts)

      end

      def self.generate_csr(cert_owner, signing_key, prov, bcProv, opts = {})

        benchmark = opts[:benchmark] || false

        isskey = signing_key.binaryValue
        signingKey = com.antrapol.kaz.jcajce.sign.KAZSIGNPrivateKey.from_encoded(isskey)

        start = BenchmarkUtils.mark_start() if benchmark
        res = BCX509.generate_csr(cert_owner, signingKey, bcProv, Proc.new do |ops|
          case ops
          when :content_signer_builder
            com.antrapol.kaz.pkix.jcejca.KAZContentSignerBuilder.new().getContentSigner(signingKey, "KAZ-SIGN", prov)
          else
            raise JrubyExPort::JrubyExPortException, "KAZ-SIGN callback operation for CSR generation not supported : #{ops}"
          end
        end)

        if benchmark
          res << BenchmarkUtils.time_taken(start)
        else
          res
        end


      end

      def self.issue_cert(cert_owner, cert_profile, prov, bcProv, opts = {})

        benchmark = opts[:benchmark] || false

        isskey = cert_profile.get(OtpErlangAtom.new("issuer_key")).binaryValue
        signingKey = com.antrapol.kaz.jcajce.sign.KAZSIGNPrivateKey.from_encoded(isskey)

        start = BenchmarkUtils.mark_start() if benchmark
        res = BCX509.issue_cert(cert_owner, cert_profile, prov, bcProv,  Proc.new do |ops|
          case ops
          when :content_signer_builder
            com.antrapol.kaz.pkix.jcejca.KAZContentSignerBuilder.new().getContentSigner(signingKey, "KAZ-SIGN", prov)
          else
            raise JrubyExPort::JrubyExPortException, "KAZ-SIGN callback operation for certificate issuance not supported : #{ops}"
          end
        end)

        if benchmark
          res << BenchmarkUtils.time_taken(start)
        else
          res
        end

      end

      #def self.generate_csr(cert_owner, signing_key, prov, bcProv, opts = {})
      #  
      #  name = to_x500_name(cert_owner)

      #  reqBuilder =  org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder.new(name, to_java_public_key(cert_owner))

      #  isskey = signing_key.binaryValue
      #  signingKey = com.antrapol.kaz.jcajce.sign.KAZSIGNPrivateKey.from_encoded(isskey)

      #  cs = com.antrapol.kaz.pkix.jcejca.KAZContentSignerBuilder.new().getContentSigner(signingKey, "KAZ-SIGN", prov)

      #  [:ok, reqBuilder.build(cs).getEncoded()]
      #  #ByteArrayOutputStream baos = new ByteArrayOutputStream();

      #  #JcaPEMWriter writer = new JcaPEMWriter(new OutputStreamWriter(baos));
      #  #writer.writeObject(req);
      #  #writer.flush();
      #  #writer.close();

      #  #FileOutputStream fos = new FileOutputStream(spec + ".csr");
      #  #fos.write(baos.toByteArray());
      #  #fos.flush();
      #  #fos.close();
      #end

      #def self.issue_cert(cert_owner, cert_profile, prov, bcProv, opts = {})
      #  
      #  #puts "#{cert_owner}"
      #  #puts "#{cert_profile}"

      #  is_issuer = cert_profile.get(OtpErlangAtom.new("is_issuer")).booleanValue
      #  is_self_sign = cert_profile.get(OtpErlangAtom.new("self_sign")).booleanValue
      #  isskey = cert_profile.get(OtpErlangAtom.new("issuer_key")).binaryValue

      #  # tuple
      #  validity = cert_profile.get(OtpErlangAtom.new("validity"))

      #  validity_val = 10
      #  validity_unit = :year
      #  if(validity != nil)
      #    val = validity.elements
      #    validity_val = val[0].intValue 
      #    validity_unit = val[1].atomValue.to_sym
      #  end

      #  signingKey = com.antrapol.kaz.jcajce.sign.KAZSIGNPrivateKey.from_encoded(isskey)

      #  isscert = cert_profile.get(OtpErlangAtom.new("issuer_cert"))
      #  isscert_obj = nil
      #  if isscert.is_a?(OtpErlangTuple)
      #    isscert_pack = isscert.elements
      #    if isscert_pack[0].atomValue.to_sym == :der
      #      isscert_obj = CertificateFactory.get_instance("X.509", bcProv).generateCertificate(java.io.ByteArrayInputStream.new(isscert_pack[1].binaryValue))
      #    else
      #      raise JrubyExportException, "Loading of certificate with format #{isscert.elements[0].atomValue} is not supported"
      #    end
      #  end


      #  sr = java.security.SecureRandom.getInstanceStrong()

      #  csr_mode = false
      #  name = nil 
      #  pubkeyObj = nil
			#	#name = nb.build()
      #  if(cert_owner.is_a?(OtpErlangBinary))
      #    # CSR
      #    rreq = org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest.new(cert_owner.binaryValue);
      #    vpbuilder = org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder.new();
      #    cvp = vpbuilder.build(rreq.getSubjectPublicKeyInfo());
      #    rreq.isSignatureValid(cvp);

      #    name = rreq.getSubject
      #    pubkeyObj = rreq.getPublicKey
      #    csr_mode = true

      #  else
      #    name = to_x500_name(cert_owner)
      #    pubkeyObj = to_java_public_key(cert_owner)
      #  end

      #  # RFC5280 max length of serial is 20 bytes
      #  # CAB mandated min 64 bits (8 bytes?)
      #  serial = nil
      #  serial_conf = cert_profile.get(OtpErlangAtom.new("serial"))
      #  if serial_conf.is_a?(OtpErlangTuple)
      #    serial_spec = serial_conf.elements
      #    if serial_spec[0].atomValue.to_sym == :random
      #      serial = java.math.BigInteger.new(1, sr.generateSeed(serial_spec[1].intValue))
      #    else
      #      serial = java.math.BigInteger.new(1, sr.generateSeed(18))
      #    end
      #  elsif serial_conf.is_a?(OtpErlangBinary)
      #    serial = java.math.BigInteger.new(1, serial_conf.binaryValue)
      #  else
      #    serial = java.math.BigInteger.new(1, sr.generateSeed(18))
      #  end

      #  validFrom = java.time.Instant.now()
      #  #validTo = validFrom.plus(2, java.time.temporal.ChronoUnit::DAYS)
      #  validTo = ZonedDateTime.now(ZoneOffset::UTC).plus(2, java.time.temporal.ChronoUnit::YEARS).to_instant()

      #  case validity_unit
      #  when :year, :years
      #    validTo = ZonedDateTime.now(ZoneOffset::UTC).plus(validity_val, java.time.temporal.ChronoUnit::YEARS).to_instant()

      #  when :month, :months
      #    validTo = ZonedDateTime.now(ZoneOffset::UTC).plus(validity_val, java.time.temporal.ChronoUnit::MONTHS).to_instant()

      #  when :week, :weeks
      #    validTo = ZonedDateTime.now(ZoneOffset::UTC).plus(validity_val, java.time.temporal.ChronoUnit::WEEKS).to_instant()

      #  when :day, :days
      #    validTo = ZonedDateTime.now(ZoneOffset::UTC).plus(validity_val, java.time.temporal.ChronoUnit::DAYS).to_instant()

      #  when :hour, :hours
      #    validTo = ZonedDateTime.now(ZoneOffset::UTC).plus(validity_val, java.time.temporal.ChronoUnit::HOURS).to_instant()

      #  when :min, :minutes, :minute
      #    validTo = ZonedDateTime.now(ZoneOffset::UTC).plus(validity_val, java.time.temporal.ChronoUnit::MINUTES).to_instant()
      #  end

      #  extUtils = org.bouncycastle.cert.bc.BcX509ExtensionUtils.new()

      #  if isscert_obj != nil
      #    cb = org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder.new(isscert_obj, serial, java.util.Date.from(validFrom),
      #      java.util.Date.from(validTo), name, pubkeyObj)
      #  else
      #    cb = org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder.new(name, serial, java.util.Date.from(validFrom),
      #      java.util.Date.from(validTo), name, pubkeyObj)
      #  end

      #  if is_self_sign
      #    puts "self-sign cert"
      #    cb.addExtension(org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier, false, extUtils
      #      .createAuthorityKeyIdentifier(org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(pubkeyObj.getEncoded)))

      #  else
      #    puts "sub ca cert"
      #    isscert = cert_profile.get(OtpErlangAtom.new("issuer_cert")).elements
      #    if isscert[0].atomValue.to_sym == :der
      #      isscert_obj = CertificateFactory.get_instance("X.509", bcProv).generateCertificate(java.io.ByteArrayInputStream.new(isscert[1].binaryValue))
      #      cb.addExtension(org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier, false, extUtils
  #.cre#ateAuthorityKeyIdentifier(org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(isscert_obj.get_public_key.get_encoded())))
      #    else
      #      raise JrubyExportException, "Loading of certificate with format #{isscert[0].atomValue} is not supported"
      #    end
      #  end

      #  cb.addExtension(org.bouncycastle.asn1.x509.Extension::subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(pubkeyObj.getEncoded)))

      #  if is_issuer
      #    puts "Issuer requested"
      #    cb.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, org.bouncycastle.asn1.x509.BasicConstraints.new(true))
      #  else
      #    puts "Non issuer requested"
      #  end

      #  # list
      #  keyUsage = cert_profile.get(OtpErlangAtom.new("key_usage")).elements
      #  kuVal = 0
      #  keyUsage.each do |ku|
      #    case ku.atomValue.to_sym
      #    when :digital_signature
      #      kuVal |= KeyUsage.digitalSignature

      #    when :non_repudiation
      #      kuVal |= KeyUsage.nonRepudiation

      #    when :key_cert_sign
      #      kuVal |= KeyUsage.keyCertSign

      #    when :crl_sign
      #      kuVal |= KeyUsage.cRLSign
      #    when :key_encipherment
      #      kuVal |= KeyUsage.keyEncipherment
      #    when :data_encipherment
      #      kuVal |= KeyUsage.dataEncipherment
      #    when :key_agreement
      #      kuVal |= KeyUsage.keyAgreement
      #    when :encipher_only
      #      kuVal |= KeyUsage.encipherOnly
      #    when :decipher_only
      #      kuVal |= KeyUsage.decipherOnly
      #    end
      #  end

			#	cb.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, false, org.bouncycastle.asn1.x509.KeyUsage.new(kuVal))

      #  extKeyUsage = cert_profile.get(OtpErlangAtom.new("ext_key_usage")).elements
      #  v = java.util.Vector.new()
      #  extKeyUsage.each do |eku|
      #    case eku.atomValue.to_sym
      #    when :server_auth
      #      v.add(KeyPurposeId.id_kp_serverAuth)
      #    when :client_auth
      #      v.add(KeyPurposeId.id_kp_clientAuth)
      #    when :code_signing
      #      v.add(KeyPurposeId.id_kp_codeSigning)
      #    when :email_protection
      #      v.add(KeyPurposeId.id_kp_emailProtection)
      #    when :timestamping
      #      v.add(KeyPurposeId.id_kp_timeStamping)
      #    when :ocsp_signing
      #      v.add(KeyPurposeId.id_kp_OCSPStamping)
      #    end
      #  end
			#	#v.add(org.bouncycastle.asn1.x509.KeyPurposeId.anyExtendedKeyUsage);

      #  cb.addExtension(org.bouncycastle.asn1.x509.Extension.extendedKeyUsage, false, org.bouncycastle.asn1.x509.ExtendedKeyUsage.new(v))

      #  if not csr_mode
      #    altName = []
      #    #csrCp.uri.uniq.each do |u|
      #    #  altName << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::uniformResourceIdentifier,u)
      #    #end

      #    cert_owner_email = cert_owner.get(com.ericsson.otp.erlang.OtpErlangAtom.new("email"))
      #    if(cert_owner_email != nil)
      #      if(cert_owner_email.is_a?(OtpErlangList))
      #        cert_owner_email.elements.each do |e|
      #          altName << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::rfc822Name,java.lang.String.new(e.binaryValue))
      #        end
      #      elsif (cert_owner_email.is_a?(OtpErlangBinary))
      #        altName << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::rfc822Name,java.lang.String.new(cert_owner_email.binaryValue))
      #      else
      #      end
      #    end

      #    cert_owner_dns = cert_owner.get(com.ericsson.otp.erlang.OtpErlangAtom.new("dns_name"))
      #    if(cert_owner_dns != nil)
      #      if(cert_owner_dns.is_a?(OtpErlangList))
      #        cert_owner_dns.elements.each do |e|
      #          altName << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::dNSName,java.lang.String.new(e.binaryValue))
      #        end
      #      elsif (cert_owner_dns.is_a?(OtpErlangBinary))
      #        altName << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::dNSName,java.lang.String.new(cert_owner_dns.binaryValue))
      #      else
      #      end
      #    end

      #    cert_owner_ips = cert_owner.get(com.ericsson.otp.erlang.OtpErlangAtom.new("ip_address"))
      #    if(cert_owner_ips != nil)
      #      if(cert_owner_ips.is_a?(OtpErlangList))
      #        cert_owner_ips.elements.each do |e|
      #          altName << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::iPAddress,java.lang.String.new(e.binaryValue))
      #        end
      #      elsif (cert_owner_ips.is_a?(OtpErlangBinary))
      #        altName << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::iPAddress,java.lang.String.new(cert_owner_ips.binaryValue))
      #      end
      #    end


      #    if altName.length > 0
      #      cb.addExtension(org.bouncycastle.asn1.x509.Extension::subjectAlternativeName, false, org.bouncycastle.asn1.x509.GeneralNames.new(altName.to_java(org.bouncycastle.asn1.x509.GeneralName)) )
      #    end

      #  end

      #  
      #  cert_profile_crl_dist_point = cert_profile.get(com.ericsson.otp.erlang.OtpErlangAtom.new("crl_dist_point"))
      #  if cert_profile_crl_dist_point != nil
      #    crls = []
      #    if(cert_profile_crl_dist_point.is_a?(OtpErlangList))
      #      cert_profile_crl_dist_point.elements.each do |c|
      #        crls << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::uniformResourceIdentifier, org.bouncycastle.asn1.DERIA5String.new(java.lang.String.new(c.binaryValue)))
      #      end
      #    elsif (cert_owner_ips.is_a?(OtpErlangBinary))
      #      crls << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::uniformResourceIdentifier, org.bouncycastle.asn1.DERIA5String.new(java.lang.String.new(cert_profile_crl_dist_point.binaryValue)))
      #    end
 
      #    gns = org.bouncycastle.asn1.x509.GeneralNames.new(crls.to_java(org.bouncycastle.asn1.x509.GeneralName))
      #    dpn = org.bouncycastle.asn1.x509.DistributionPointName.new(gns)
      #    dp =  org.bouncycastle.asn1.x509.DistributionPoint.new(dpn,nil,nil)
      #    cb.addExtension(org.bouncycastle.asn1.x509.X509Extensions::CRLDistributionPoints,false,org.bouncycastle.asn1.DERSequence.new(dp))      
      #  end

      #  aia = []
      #  cp_ocsp = cert_profile.get(com.ericsson.otp.erlang.OtpErlangAtom.new("ocsp_url"))
      #  if cp_ocsp != nil
      #    if(cp_ocsp.is_a?(OtpErlangList))
      #      cp_ocsp.elements.each do |c|
      #        ov = org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::uniformResourceIdentifier, org.bouncycastle.asn1.DERIA5String.new(java.lang.String.new(c.binaryValue)))
      #        aia << org.bouncycastle.asn1.x509.AccessDescription.new(org.bouncycastle.asn1.x509.AccessDescription.id_ad_ocsp, ov)
      #      end
      #    elsif (cp_ocsp.is_a?(OtpErlangBinary))
      #        ov = org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::uniformResourceIdentifier, org.bouncycastle.asn1.DERIA5String.new(java.lang.String.new(cp_ocsp.binaryValue)))
      #        aia << org.bouncycastle.asn1.x509.AccessDescription.new(org.bouncycastle.asn1.x509.AccessDescription.id_ad_ocsp, ov)
      #    end
      #  end

      #  cp_ts = cert_profile.get(com.ericsson.otp.erlang.OtpErlangAtom.new("timestamping_url"))
      #  if cp_ts != nil
      #    timestampAsn1 = org.bouncycastle.asn1.ASN1ObjectIdentifier.new("1.3.6.1.5.5.7.48.3") # id_ad_timeStamping
      #    if(cp_ts.is_a?(OtpErlangList))
      #      cp_ts.elements.each do |c|
      #        ov = org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::uniformResourceIdentifier, org.bouncycastle.asn1.DERIA5String.new(java.lang.String.new(c.binaryValue)))
      #        aia << org.bouncycastle.asn1.x509.AccessDescription.new(timestampAsn1, ov)
      #      end
      #    elsif (cp_ts.is_a?(OtpErlangBinary))
      #        ov = org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::uniformResourceIdentifier, org.bouncycastle.asn1.DERIA5String.new(java.lang.String.new(cp_ts.binaryValue)))
      #        aia << org.bouncycastle.asn1.x509.AccessDescription.new(timestampAsn1, ov)
      #    end
      #  end


      #  cp_issuer = cert_profile.get(com.ericsson.otp.erlang.OtpErlangAtom.new("issuer_url"))
      #  if cp_issuer != nil
      #    if(cp_issuer.is_a?(OtpErlangList))
      #      cp_issuer.elements.each do |c|
      #        ov = org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::uniformResourceIdentifier, org.bouncycastle.asn1.DERIA5String.new(java.lang.String.new(c.binaryValue)))
      #        aia << org.bouncycastle.asn1.x509.AccessDescription.new(org.bouncycastle.asn1.x509.AccessDescription.id_ad_caIssuers, ov)
      #      end
      #    elsif (cp_issuer.is_a?(OtpErlangBinary))
      #        ov = org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::uniformResourceIdentifier, org.bouncycastle.asn1.DERIA5String.new(java.lang.String.new(cp_issuer.binaryValue)))
      #        aia << org.bouncycastle.asn1.x509.AccessDescription.new(org.bouncycastle.asn1.x509.AccessDescription.id_ad_caIssuers, ov)
      #    end
      #  end

      #  if aia.length > 0
      #    authorityInformationAccess = org.bouncycastle.asn1.x509.AuthorityInformationAccess.new(aia.to_java(org.bouncycastle.asn1.x509.AccessDescription))
      #    cb.addExtension(org.bouncycastle.asn1.x509.X509Extensions::AuthorityInfoAccess, false, authorityInformationAccess)			  
      #  end

      #  csb = com.antrapol.kaz.pkix.jcejca.KAZContentSignerBuilder.new().getContentSigner(signingKey, "KAZ-SIGN", prov);
      #  rc = org.bouncycastle.cert.jcajce.JcaX509CertificateConverter.new().setProvider(bcProv).getCertificate(cb.build(csb));

      #  [:ok, rc.getEncoded(), [rc.getEncoded()]]
      #end # issue_cert

      #def self.to_java_public_key(owner)

      #  subjpubkey = owner.get(com.ericsson.otp.erlang.OtpErlangAtom.new("public_key")).elements
      #  case subjpubkey[0].atomValue.to_sym
      #  when :kaz_sign_128, :kaz_sign_192, :kaz_sign_256
      #    com.antrapol.kaz.jcajce.sign.KAZSIGNPublicKey.from_encoded(subjpubkey[2].binaryValue)
      #  else
      #    raise JrubyExPort::JrubyExPortException, "Unsupported subject public key : #{subjpubkey.atomValue}"
      #  end
      #  
      #end

      #def self.to_x500_name(owner)
      #  nb = org.bouncycastle.asn1.x500.X500NameBuilder.new()

      #  puts "Owner : #{owner}"

      #  # Subject DN - CN
      #  cert_owner_name = owner.get(com.ericsson.otp.erlang.OtpErlangAtom.new("name")).binaryValue
      #  nb.addRDN(org.bouncycastle.asn1.x500.style.BCStyle::CN, java.lang.String.new(cert_owner_name))

      #  # Subject DN - OU
      #  cert_owner_ou = owner.get(com.ericsson.otp.erlang.OtpErlangAtom.new("org_unit"))
      #  if cert_owner_ou != nil 
      #    if cert_owner_ou.is_a?(OtpErlangList)
      #      cert_owner_ou.elements.each do |ouval|
      #        nb.addRDN(org.bouncycastle.asn1.x500.style.BCStyle::OU, java.lang.String.new(ouval.binaryValue))
      #      end
      #    elsif cert_owner_ou.is_a?(OtpErlangBinary)
      #      nb.addRDN(org.bouncycastle.asn1.x500.style.BCStyle::OU, java.lang.String.new(cert_owner_ou.binaryValue))
      #    end
      #  end

      #  # Subject DN - Org
      #  cert_owner_org = owner.get(com.ericsson.otp.erlang.OtpErlangAtom.new("org"))
      #  if cert_owner_org != nil
      #    nb.addRDN(org.bouncycastle.asn1.x500.style.BCStyle::O, java.lang.String.new(cert_owner_org.binaryValue))
      #  end

			#	nb.build()
      #end # to_x500_name



    end
  end
end
