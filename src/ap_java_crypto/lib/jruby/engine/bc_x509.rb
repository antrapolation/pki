java_import java.security.cert.CertificateFactory

java_import java.time.ZonedDateTime
java_import java.time.ZoneOffset

java_import com.antrapol.kaz.jcajce.sign.KAZSIGNKeyGenParameterSpec

java_import org.bouncycastle.pkcs.PKCS10CertificationRequest
java_import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest
java_import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
java_import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder

java_import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
java_import org.bouncycastle.asn1.x509.GeneralName
java_import org.bouncycastle.asn1.x509.GeneralNames
java_import org.bouncycastle.asn1.x509.ExtensionsGenerator
java_import org.bouncycastle.asn1.x509.Extensions

java_import org.bouncycastle.asn1.x509.KeyUsage
java_import org.bouncycastle.asn1.x509.KeyPurposeId

java_import com.ericsson.otp.erlang.OtpErlangAtom
java_import com.ericsson.otp.erlang.OtpErlangLong
java_import com.ericsson.otp.erlang.OtpErlangString



module ApJavaCrypto
  module Engine
    class BCX509
      def self.generate_csr(cert_owner, signing_key, bcProv, opts)

        name = to_x500_name(cert_owner)

        reqBuilder =  JcaPKCS10CertificationRequestBuilder.new(name, to_java_public_key(cert_owner, bcProv))

        altName = []

        cert_owner_email = cert_owner.get(com.ericsson.otp.erlang.OtpErlangAtom.new("email"))
        if(cert_owner_email != nil)
          if(cert_owner_email.is_a?(OtpErlangList))
            cert_owner_email.elements.each do |e|
              altName << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::rfc822Name,java.lang.String.new(e.binaryValue))
            end
          elsif (cert_owner_email.is_a?(OtpErlangBinary))
            altName << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::rfc822Name,java.lang.String.new(cert_owner_email.binaryValue))
          else
          end
        end

        cert_owner_dns = cert_owner.get(com.ericsson.otp.erlang.OtpErlangAtom.new("dns_name"))
        if(cert_owner_dns != nil)
          if(cert_owner_dns.is_a?(OtpErlangList))
            cert_owner_dns.elements.each do |e|
              altName << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::dNSName,java.lang.String.new(e.binaryValue))
            end
          elsif (cert_owner_dns.is_a?(OtpErlangBinary))
            altName << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::dNSName,java.lang.String.new(cert_owner_dns.binaryValue))
          else
          end
        end

        cert_owner_ips = cert_owner.get(com.ericsson.otp.erlang.OtpErlangAtom.new("ip_address"))
        if(cert_owner_ips != nil)
          if(cert_owner_ips.is_a?(OtpErlangList))
            cert_owner_ips.elements.each do |e|
              altName << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::iPAddress,java.lang.String.new(e.binaryValue))
            end
          elsif (cert_owner_ips.is_a?(OtpErlangBinary))
            altName << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::iPAddress,java.lang.String.new(cert_owner_ips.binaryValue))
          end
        end


        if altName.length > 0

          extGen = ExtensionsGenerator.new();

          extGen.addExtension(org.bouncycastle.asn1.x509.Extension::subjectAlternativeName, false, org.bouncycastle.asn1.x509.GeneralNames.new(altName.to_java(org.bouncycastle.asn1.x509.GeneralName)) )

          reqBuilder.addAttribute(
            PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
            extGen.generate()
          )
        end

        cs = opts.call(:content_signer_builder)

        req = reqBuilder.build(cs)

        [:ok, req.getEncoded]
      end

      def self.verify_csr(csr, bcProv, opts = {})
       
        return_csr_info = opts[:return_csr_info] || false

        begin
          rreq = JcaPKCS10CertificationRequest.new(csr);
          cvp = JcaContentVerifierProviderBuilder.new().build(rreq.getSubjectPublicKeyInfo())
          res = rreq.isSignatureValid(cvp)

          subject = rreq.getSubject().to_s
          pubkey = org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter.new().getPublicKey(rreq.getSubjectPublicKeyInfo())
          salgo = rreq.getSignatureAlgorithm().getAlgorithm

          #if callback
          #  callback.call(:verify_csr, res, rreq)
          #end

          if return_csr_info
            [:ok, res, {subject: subject, pubkey_algo: pubkey.get_algorithm, sign_algo: salgo.getId().to_s, pubkey_bin: java.math.BigInteger.new(pubkey.getEncoded()).to_string(16) }]
          else
            [:ok, res]
          end
        rescue StandardError => exception
          puts exception.message
          puts exception.backtrace.join("\n")
          [:error, exception] 
        end
      end

      def self.cert_verify_issuer(subj, issuer, opts = {})

        subjcert = to_java_cert(subj)
        isscert = to_java_cert(issuer)

        if (!subjcert.getIssuerX500Principal().equals(isscert.getSubjectX500Principal())) 
          raise java.security.cert.CertificateException.new("Issuer DN does not match value on subject certificate")
        end

        begin
          subjcert.verify(isscert.get_public_key)
          [:ok, true]

        rescue java.lang.Exception => ex
          puts ex.backtrace.join("\n")
          [:error, false, ex.message]  
        rescue StandardError => ex
          puts ex.backtrace.join("\n")
          [:error, false, ex.message]  
        end

      end

      def self.verify_cert_validity(subject, reference = :now, opts = {})
        subjcert = to_java_cert(subject)

        validTo = ZonedDateTime.now(ZoneOffset::UTC)
        #validTo = validTo.minus(1, java.time.temporal.ChronoUnit::YEARS)
        #validTo = validTo.plus(1, java.time.temporal.ChronoUnit::YEARS)

        subjcert.check_validity(java.util.Date.from(validTo.to_instant))

        [:ok, true]
      end

      def self.issue_cert(cert_owner, cert_profile, prov, bcProv, opts = {})

        #puts "#{cert_owner}"
        #puts "#{cert_profile}"

        is_issuer = cert_profile.get(OtpErlangAtom.new("is_issuer")).booleanValue
        is_self_sign = cert_profile.get(OtpErlangAtom.new("self_sign")).booleanValue
        #isskey = cert_profile.get(OtpErlangAtom.new("issuer_key")).binaryValue

        # tuple
        validity = cert_profile.get(OtpErlangAtom.new("validity"))

        validity_val = 10
        validity_unit = :year
        validity_conf = {}
        if(validity != nil)
          val = validity.elements
          val.each do |v|
            if v.is_a?(OtpErlangTuple)
              vv = v.elements
              validity_val = vv[0].intValue 
              validity_unit = vv[1].atomValue.to_sym
            else
              validity_val = val[0].intValue 
              validity_unit = val[1].atomValue.to_sym
            end
            validity_conf[validity_unit] = validity_val
          end
        end

        #signingKey = com.antrapol.kaz.jcajce.sign.KAZSIGNPrivateKey.from_encoded(isskey)

        isscert = cert_profile.get(OtpErlangAtom.new("issuer_cert"))
        isscert_obj = nil
        if isscert.is_a?(OtpErlangTuple)
          isscert_pack = isscert.elements
          # should received {der, {:ap_java_crypto, cert}}
          if isscert_pack[0].atomValue.to_sym == :der
            if isscert_pack[1].is_a?(OtpErlangTuple)
              # {:ap_java_crypto, cert}
              isscert_obj = CertificateFactory.get_instance("X.509", bcProv).generateCertificate(java.io.ByteArrayInputStream.new(isscert_pack[1].elements[1].binaryValue))
            else
              isscert_obj = CertificateFactory.get_instance("X.509", bcProv).generateCertificate(java.io.ByteArrayInputStream.new(isscert_pack[1].binaryValue))
            end
          else
            raise JrubyExPort::JrubyExPortException, "Loading of certificate with format #{isscert.elements[0].atomValue} is not supported"
          end
        end


        sr = java.security.SecureRandom.getInstanceStrong()

        csr_mode = false
        name = nil 
        pubkeyObj = nil
        #name = nb.build()
        if(cert_owner.is_a?(OtpErlangBinary))
          # CSR
          rreq = org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest.new(cert_owner.binaryValue);
          vpbuilder = org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder.new();
          cvp = vpbuilder.build(rreq.getSubjectPublicKeyInfo());
          rreq.isSignatureValid(cvp);

          name = rreq.getSubject
          pubkeyObj = rreq.getPublicKey
          csr_mode = true

        else
          name = to_x500_name(cert_owner)
          pubkeyObj = to_java_public_key(cert_owner, bcProv)
        end

        # RFC5280 max length of serial is 20 bytes
        # CAB mandated min 64 bits (8 bytes?)
        serial = nil
        serial_conf = cert_profile.get(OtpErlangAtom.new("serial"))
        if serial_conf.is_a?(OtpErlangTuple)
          serial_spec = serial_conf.elements
          if serial_spec[0].atomValue.to_sym == :random
            serial = java.math.BigInteger.new(1, sr.generateSeed(serial_spec[1].intValue))
          else
            serial = java.math.BigInteger.new(1, sr.generateSeed(18))
          end
        elsif serial_conf.is_a?(OtpErlangBinary)
          serial = java.math.BigInteger.new(1, serial_conf.binaryValue)
        else
          serial = java.math.BigInteger.new(1, sr.generateSeed(18))
        end

        validFrom = java.time.Instant.now()
        #validTo = validFrom.plus(2, java.time.temporal.ChronoUnit::DAYS)
        #validTo = ZonedDateTime.now(ZoneOffset::UTC).plus(2, java.time.temporal.ChronoUnit::YEARS).to_instant()
        validTo = ZonedDateTime.now(ZoneOffset::UTC)

        validity_conf.each do |validity_unit, validity_val|
          
          case validity_unit
          when :year, :years
            validTo = validTo.plus(validity_val, java.time.temporal.ChronoUnit::YEARS)

          when :month, :months
            validTo = validTo.plus(validity_val, java.time.temporal.ChronoUnit::MONTHS)

          when :week, :weeks
            validTo = validTo.plus(validity_val, java.time.temporal.ChronoUnit::WEEKS)

          when :day, :days
            validTo = validTo.plus(validity_val, java.time.temporal.ChronoUnit::DAYS)

          when :hour, :hours
            validTo = validTo.plus(validity_val, java.time.temporal.ChronoUnit::HOURS)

          when :min, :minutes, :minute
            validTo = validTo.plus(validity_val, java.time.temporal.ChronoUnit::MINUTES)
          end
        end

        validTo = validTo.to_instant()
        #validTo = ZonedDateTime.now(ZoneOffset::UTC).plus(validity_val, java.time.temporal.ChronoUnit::YEARS).to_instant()

        extUtils = org.bouncycastle.cert.bc.BcX509ExtensionUtils.new()

        if isscert_obj != nil
          cb = org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder.new(isscert_obj, serial, java.util.Date.from(validFrom),
            java.util.Date.from(validTo), name, pubkeyObj)
        else
          cb = org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder.new(name, serial, java.util.Date.from(validFrom),
            java.util.Date.from(validTo), name, pubkeyObj)
        end

        if is_self_sign
          puts "self-sign cert"
          cb.addExtension(org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier, false, extUtils
            .createAuthorityKeyIdentifier(org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(pubkeyObj.getEncoded)))

        else
          puts "sub ca cert"
          isscert = cert_profile.get(OtpErlangAtom.new("issuer_cert")).elements
          puts "sub ca cert : #{isscert}"
          if isscert[0].atomValue.to_sym == :der
            if isscert[1].is_a?(OtpErlangTuple)
              # {:ap_java_crypto, cert}
              isscert_obj = CertificateFactory.get_instance("X.509", bcProv).generateCertificate(java.io.ByteArrayInputStream.new(isscert_pack[1].elements[1].binaryValue))
            else
              isscert_obj = CertificateFactory.get_instance("X.509", bcProv).generateCertificate(java.io.ByteArrayInputStream.new(isscert_pack[1].binaryValue))
            end

            #isscert_obj = CertificateFactory.get_instance("X.509", bcProv).generateCertificate(java.io.ByteArrayInputStream.new(isscert[1].binaryValue))
            cb.addExtension(org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier, false, extUtils
              .createAuthorityKeyIdentifier(org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(isscert_obj.get_public_key.get_encoded())))
          else
            raise JrubyExPort::JrubyExportException, "Loading of certificate with format #{isscert[0].atomValue} is not supported"
          end
        end

        cb.addExtension(org.bouncycastle.asn1.x509.Extension::subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(pubkeyObj.getEncoded)))

        if is_issuer
          puts "Issuer requested"
          cb.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, org.bouncycastle.asn1.x509.BasicConstraints.new(true))
        else
          puts "Non issuer requested"
        end

        # list
        keyUsage = cert_profile.get(OtpErlangAtom.new("key_usage")).elements
        kuVal = 0
        keyUsage.each do |ku|
          case ku.atomValue.to_sym
          when :digital_signature
            kuVal |= KeyUsage.digitalSignature

          when :non_repudiation
            kuVal |= KeyUsage.nonRepudiation

          when :key_cert_sign
            kuVal |= KeyUsage.keyCertSign

          when :crl_sign
            kuVal |= KeyUsage.cRLSign
          when :key_encipherment
            kuVal |= KeyUsage.keyEncipherment
          when :data_encipherment
            kuVal |= KeyUsage.dataEncipherment
          when :key_agreement
            kuVal |= KeyUsage.keyAgreement
          when :encipher_only
            kuVal |= KeyUsage.encipherOnly
          when :decipher_only
            kuVal |= KeyUsage.decipherOnly
          end
        end

        cb.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, false, org.bouncycastle.asn1.x509.KeyUsage.new(kuVal))

        extKeyUsage = cert_profile.get(OtpErlangAtom.new("ext_key_usage")).elements
        v = java.util.Vector.new()
        extKeyUsage.each do |eku|
          case eku.atomValue.to_sym
          when :server_auth
            v.add(KeyPurposeId.id_kp_serverAuth)
          when :client_auth
            v.add(KeyPurposeId.id_kp_clientAuth)
          when :code_signing
            v.add(KeyPurposeId.id_kp_codeSigning)
          when :email_protection
            v.add(KeyPurposeId.id_kp_emailProtection)
          when :timestamping
            v.add(KeyPurposeId.id_kp_timeStamping)
          when :ocsp_signing
            v.add(KeyPurposeId.id_kp_OCSPSigning)
          end
        end
        #v.add(org.bouncycastle.asn1.x509.KeyPurposeId.anyExtendedKeyUsage);

        cb.addExtension(org.bouncycastle.asn1.x509.Extension.extendedKeyUsage, false, org.bouncycastle.asn1.x509.ExtendedKeyUsage.new(v))

        if not csr_mode
          puts "Direct value setting"
          altName = []
          #csrCp.uri.uniq.each do |u|
          #  altName << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::uniformResourceIdentifier,u)
          #end

          cert_owner_email = cert_owner.get(com.ericsson.otp.erlang.OtpErlangAtom.new("email"))
          if(cert_owner_email != nil)
            if(cert_owner_email.is_a?(OtpErlangList))
              cert_owner_email.elements.each do |e|
                altName << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::rfc822Name,java.lang.String.new(e.binaryValue))
              end
            elsif (cert_owner_email.is_a?(OtpErlangBinary))
              altName << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::rfc822Name,java.lang.String.new(cert_owner_email.binaryValue))
            else
            end
          end

          cert_owner_dns = cert_owner.get(com.ericsson.otp.erlang.OtpErlangAtom.new("dns_name"))
          if(cert_owner_dns != nil)
            if(cert_owner_dns.is_a?(OtpErlangList))
              cert_owner_dns.elements.each do |e|
                altName << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::dNSName,java.lang.String.new(e.binaryValue))
              end
            elsif (cert_owner_dns.is_a?(OtpErlangBinary))
              altName << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::dNSName,java.lang.String.new(cert_owner_dns.binaryValue))
            else
            end
          end

          cert_owner_ips = cert_owner.get(com.ericsson.otp.erlang.OtpErlangAtom.new("ip_address"))
          if(cert_owner_ips != nil)
            if(cert_owner_ips.is_a?(OtpErlangList))
              cert_owner_ips.elements.each do |e|
                altName << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::iPAddress,java.lang.String.new(e.binaryValue))
              end
            elsif (cert_owner_ips.is_a?(OtpErlangBinary))
              altName << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::iPAddress,java.lang.String.new(cert_owner_ips.binaryValue))
            end
          end


          if altName.length > 0
            cb.addExtension(org.bouncycastle.asn1.x509.Extension::subjectAlternativeName, false, org.bouncycastle.asn1.x509.GeneralNames.new(altName.to_java(org.bouncycastle.asn1.x509.GeneralName)) )
          end

        else 
          puts "Copy from CSR"
          # copy from CSR
          requestedExtensions = nil
          attrs = rreq.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)
          if (attrs != nil && attrs.length > 0) 
            attrValues = attrs[0].getAttrValues()
            if (attrValues.size() > 0) 
              requestedExtensions = Extensions.getInstance(attrValues.getObjectAt(0))
            end
          end

          if requestedExtensions != nil
            requestedExtensions.getExtensionOIDs.each do |oid|
              ext = requestedExtensions.getExtension(oid)
              cb.addExtension(oid, ext.isCritical(), ext.getParsedValue());
            end
          end

        end


        cert_profile_crl_dist_point = cert_profile.get(com.ericsson.otp.erlang.OtpErlangAtom.new("crl_dist_point"))
        if cert_profile_crl_dist_point != nil
          crls = []
          if(cert_profile_crl_dist_point.is_a?(OtpErlangList))
            cert_profile_crl_dist_point.elements.each do |c|
              crls << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::uniformResourceIdentifier, org.bouncycastle.asn1.DERIA5String.new(java.lang.String.new(c.binaryValue)))
            end
          elsif (cert_owner_ips.is_a?(OtpErlangBinary))
            crls << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::uniformResourceIdentifier, org.bouncycastle.asn1.DERIA5String.new(java.lang.String.new(cert_profile_crl_dist_point.binaryValue)))
          end

          gns = org.bouncycastle.asn1.x509.GeneralNames.new(crls.to_java(org.bouncycastle.asn1.x509.GeneralName))
          dpn = org.bouncycastle.asn1.x509.DistributionPointName.new(gns)
          dp =  org.bouncycastle.asn1.x509.DistributionPoint.new(dpn,nil,nil)
          cb.addExtension(org.bouncycastle.asn1.x509.X509Extensions::CRLDistributionPoints,false,org.bouncycastle.asn1.DERSequence.new(dp))      
        end

        aia = []
        cp_ocsp = cert_profile.get(com.ericsson.otp.erlang.OtpErlangAtom.new("ocsp_url"))
        if cp_ocsp != nil
          if(cp_ocsp.is_a?(OtpErlangList))
            cp_ocsp.elements.each do |c|
              ov = org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::uniformResourceIdentifier, org.bouncycastle.asn1.DERIA5String.new(java.lang.String.new(c.binaryValue)))
              aia << org.bouncycastle.asn1.x509.AccessDescription.new(org.bouncycastle.asn1.x509.AccessDescription.id_ad_ocsp, ov)
            end
          elsif (cp_ocsp.is_a?(OtpErlangBinary))
            ov = org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::uniformResourceIdentifier, org.bouncycastle.asn1.DERIA5String.new(java.lang.String.new(cp_ocsp.binaryValue)))
            aia << org.bouncycastle.asn1.x509.AccessDescription.new(org.bouncycastle.asn1.x509.AccessDescription.id_ad_ocsp, ov)
          end
        end

        cp_ts = cert_profile.get(com.ericsson.otp.erlang.OtpErlangAtom.new("timestamping_url"))
        if cp_ts != nil
          timestampAsn1 = org.bouncycastle.asn1.ASN1ObjectIdentifier.new("1.3.6.1.5.5.7.48.3") # id_ad_timeStamping
          if(cp_ts.is_a?(OtpErlangList))
            cp_ts.elements.each do |c|
              ov = org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::uniformResourceIdentifier, org.bouncycastle.asn1.DERIA5String.new(java.lang.String.new(c.binaryValue)))
              aia << org.bouncycastle.asn1.x509.AccessDescription.new(timestampAsn1, ov)
            end
          elsif (cp_ts.is_a?(OtpErlangBinary))
            ov = org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::uniformResourceIdentifier, org.bouncycastle.asn1.DERIA5String.new(java.lang.String.new(cp_ts.binaryValue)))
            aia << org.bouncycastle.asn1.x509.AccessDescription.new(timestampAsn1, ov)
          end
        end


        cp_issuer = cert_profile.get(com.ericsson.otp.erlang.OtpErlangAtom.new("issuer_url"))
        if cp_issuer != nil
          if(cp_issuer.is_a?(OtpErlangList))
            cp_issuer.elements.each do |c|
              ov = org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::uniformResourceIdentifier, org.bouncycastle.asn1.DERIA5String.new(java.lang.String.new(c.binaryValue)))
              aia << org.bouncycastle.asn1.x509.AccessDescription.new(org.bouncycastle.asn1.x509.AccessDescription.id_ad_caIssuers, ov)
            end
          elsif (cp_issuer.is_a?(OtpErlangBinary))
            ov = org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::uniformResourceIdentifier, org.bouncycastle.asn1.DERIA5String.new(java.lang.String.new(cp_issuer.binaryValue)))
            aia << org.bouncycastle.asn1.x509.AccessDescription.new(org.bouncycastle.asn1.x509.AccessDescription.id_ad_caIssuers, ov)
          end
        end

        if aia.length > 0
          authorityInformationAccess = org.bouncycastle.asn1.x509.AuthorityInformationAccess.new(aia.to_java(org.bouncycastle.asn1.x509.AccessDescription))
          cb.addExtension(org.bouncycastle.asn1.x509.X509Extensions::AuthorityInfoAccess, false, authorityInformationAccess)			  
        end

        #csb = com.antrapol.kaz.pkix.jcejca.KAZContentSignerBuilder.new().getContentSigner(signingKey, "KAZ-SIGN", prov);
        csb = opts.call(:content_signer_builder)
        rc = org.bouncycastle.cert.jcajce.JcaX509CertificateConverter.new().setProvider(bcProv).getCertificate(cb.build(csb));

        [:ok, rc.getEncoded(), [rc.getEncoded()]]
      end # issue_cert

      def self.to_java_public_key(owner, prov = nil)

        subjpubkey = owner.get(com.ericsson.otp.erlang.OtpErlangAtom.new("public_key")).elements
        #case subjpubkey[0].atomValue.to_sym
        #when :kaz_sign_128, :kaz_sign_192, :kaz_sign_256
        case subjpubkey[0].atomValue
        when /^kaz_sign/ 
          com.antrapol.kaz.jcajce.sign.KAZSIGNPublicKey.from_encoded(subjpubkey[2].binaryValue)
        when /^ml_dsa/
          kf = java.security.KeyFactory.getInstance("ML-DSA", prov)
          kf.generatePublic(JcaJceCommon.load_public_key(subjpubkey[2].binaryValue))
        when /^slh_dsa/
          kf = java.security.KeyFactory.getInstance("SLH-DSA", prov)
          kf.generatePublic(JcaJceCommon.load_public_key(subjpubkey[2].binaryValue))
        when /^kaz_kem/ 
          com.antrapol.kaz.jcajce.kem.KAZKEMPublicKey.from_encoded(subjpubkey[2].binaryValue)
        when /^ml_kem/
          kf = java.security.KeyFactory.getInstance("ML-KEM", prov)
          kf.generatePublic(JcaJceCommon.load_public_key(subjpubkey[2].binaryValue))
        else
          raise JrubyExPort::JrubyExPortException, "Unsupported subject public key : #{subjpubkey[0].atomValue}"
        end

      end

      def self.to_x500_name(owner)
        nb = org.bouncycastle.asn1.x500.X500NameBuilder.new()

        puts "Owner : #{owner}"

        # Subject DN - CN
        cert_owner_name = owner.get(com.ericsson.otp.erlang.OtpErlangAtom.new("name")).binaryValue
        nb.addRDN(org.bouncycastle.asn1.x500.style.BCStyle::CN, java.lang.String.new(cert_owner_name))

        # Subject DN - OU
        cert_owner_ou = owner.get(com.ericsson.otp.erlang.OtpErlangAtom.new("org_unit"))
        if cert_owner_ou != nil 
          if cert_owner_ou.is_a?(OtpErlangList)
            cert_owner_ou.elements.each do |ouval|
              nb.addRDN(org.bouncycastle.asn1.x500.style.BCStyle::OU, java.lang.String.new(ouval.binaryValue))
            end
          elsif cert_owner_ou.is_a?(OtpErlangBinary)
            nb.addRDN(org.bouncycastle.asn1.x500.style.BCStyle::OU, java.lang.String.new(cert_owner_ou.binaryValue))
          end
        end

        # Subject DN - Org
        cert_owner_org = owner.get(com.ericsson.otp.erlang.OtpErlangAtom.new("org"))
        if cert_owner_org != nil
          nb.addRDN(org.bouncycastle.asn1.x500.style.BCStyle::O, java.lang.String.new(cert_owner_org.binaryValue))
        end

        # Subject DN - Country
        cert_owner_country = owner.get(com.ericsson.otp.erlang.OtpErlangAtom.new("country"))
        puts "cert_owner_country : #{cert_owner_country} / #{cert_owner_country.class}"
        if cert_owner_country.is_a?(OtpErlangBinary)
          #cert_owner_country = cert_owner_country.atomValue.to_s
          nb.addRDN(org.bouncycastle.asn1.x500.style.BCStyle::C, java.lang.String.new(cert_owner_country.binaryValue))
        end

        nb.build()
      end # to_x500_name

      def self.to_java_cert(cert)

        puts "cert to convert : #{cert}"
        CertificateFactory.get_instance("X.509", ApJavaCrypto::BCProv).generateCertificate(java.io.ByteArrayInputStream.new(cert.binaryValue))
        
        #if cert[0].atomValue.to_sym == :der
        #  if cert[1].is_a?(OtpErlangTuple)
        #    # {:ap_java_crypto, cert}
        #    CertificateFactory.get_instance("X.509", bcProv).generateCertificate(java.io.ByteArrayInputStream.new(cert[1].elements[1].binaryValue))
        #  else
        #    CertificateFactory.get_instance("X.509", bcProv).generateCertificate(java.io.ByteArrayInputStream.new(cert[1].binaryValue))
        #  end
        #else
        #  raise JrubyExPort::JrubyExPortException, "Loading of certificate with format #{cert[0].atomValue} is not supported"
        #end

      end 
    end
  end
end
