
# x509_parser.rb
require 'java'
java_import 'java.io.ByteArrayInputStream'
java_import 'java.security.cert.CertificateFactory'
java_import 'java.security.cert.X509Certificate'
java_import 'java.util.Base64'

module ApJavaCrypto
  module X509Parser
    module_function

    def parse(cert_data)
      cert_bytes = cert_data.binaryValue

      # Parse X.509 certificate
      cf = CertificateFactory.getInstance("X.509")
      cert = cf.generateCertificate(ByteArrayInputStream.new(cert_bytes))

      [:ok, {
        subject: cert.getSubjectX500Principal.getName.split(","),
        issuer: cert.getIssuerX500Principal.getName.split(","),
        serial_number: cert.getSerialNumber.to_s(16),
        not_before: cert.getNotBefore.to_instant.at_zone(java.time.ZoneId.of("UCT")).format(java.time.format.DateTimeFormatter::ISO_OFFSET_DATE_TIME),
        not_after: cert.getNotAfter.to_instant.at_zone(java.time.ZoneId.of("UCT")).format(java.time.format.DateTimeFormatter::ISO_OFFSET_DATE_TIME),
        signature_algorithm: cert.getSigAlgName,
        version: cert.getVersion,
        public_key_algorithm: cert.getPublicKey.getAlgorithm,
        public_key_format: cert.getPublicKey.getFormat,
        public_key: cert.getPublicKey.getEncoded,
        extensions: extract_extensions(cert),
        signature: cert.getSignature,
        raw_cert: cert_bytes
      }]
    end

    def extract_extensions(cert)
      result = {}

      # Subject Alternative Names
      san = parse_san(cert)
      result[:subjectAltName] = san if san

      # Key Usage
      ku = parse_key_usage(cert)
      result[:keyUsage] = ku if ku

      # Extended Key Usage
      eku = parse_extended_key_usage(cert)
      result[:extKeyUsage] = eku if eku

      # Basic Constraints
      bc = parse_basic_constraints(cert)
      result[:basicConstraints] = bc if bc

      # Subject Key Identifier
      ski = parse_subject_key_identifier(cert)
      result[:subjectKeyID] = ski if ski

      # Authority Key Identifier
      aki = parse_authority_key_identifier(cert)
      result[:authorityKeyID] = aki if aki

      # Include all other raw extensions
      #(cert.getNonCriticalExtensionOIDs || []).each do |oid|
      #  next if result.keys.any? { |k| k.start_with?(oid) }
      #  result[oid] = { critical: false, value: bytes_to_hex(cert.getExtensionValue(oid)) }
      #end
      #(cert.getCriticalExtensionOIDs || []).each do |oid|
      #  next if result.keys.any? { |k| k.start_with?(oid) }
      #  result[oid] = { critical: true, value: bytes_to_hex(cert.getExtensionValue(oid)) }
      #end

      result
    end

    # ---- Common extension parsers ----

    def parse_san(cert)
      san_list = cert.getSubjectAlternativeNames
      return nil unless san_list
      san_list.map do |entry|
        type, value = entry.to_a
        case type
        when 1 then { type: 'rfc822Name', value: value }   # email
        when 2 then { type: 'DNSName', value: value }
        when 6 then { type: 'URI', value: value }
        when 7 then { type: 'IPAddress', value: value }
        else { type: "#{type}", value: value }
        end
      end
    rescue
      nil
    end

    def parse_key_usage(cert)
      bits = cert.getKeyUsage
      if bits
        names = %w[digitalSignature nonRepudiation keyEncipherment dataEncipherment keyAgreement keyCertSign cRLSign encipherOnly decipherOnly]
        return bits.each_with_index.map { |flag, i| names[i] if flag }.compact
      end

      # Fallback: decode from raw bytes if present
      raw = cert.getExtensionValue("2.5.29.15")
      return nil unless raw
      decoded = decode_bit_string(raw)
      names = %w[digitalSignature nonRepudiation keyEncipherment dataEncipherment keyAgreement keyCertSign cRLSign encipherOnly decipherOnly]
      bits = decoded.map.with_index { |bit, i| names[i] if bit }.compact
      bits
    end

    def decode_bit_string(ext_bytes)
      # Strip the DER OCTET STRING wrapper and extract the BIT STRING
      stream = java.io.ByteArrayInputStream.new(ext_bytes)
      der = org.bouncycastle.asn1.ASN1InputStream.new(stream)
      obj = der.readObject
      bit_string = org.bouncycastle.asn1.ASN1BitString.getInstance(obj)
      bytes = bit_string.getBytes
      bits = []
      bytes.each_with_index do |b, i|
        8.times do |bit|
          bits << ((b >> (7 - bit)) & 1) == 1
        end
      end
      bits
    rescue
      []
    end

    def parse_extended_key_usage(cert)
      list = cert.getExtendedKeyUsage
      return nil unless list
      list.map do |oid|
        case oid
        when "1.3.6.1.5.5.7.3.1" then "serverAuth"
        when "1.3.6.1.5.5.7.3.2" then "clientAuth"
        when "1.3.6.1.5.5.7.3.3" then "codeSigning"
        when "1.3.6.1.5.5.7.3.4" then "emailProtection"
        when "1.3.6.1.5.5.7.3.8" then "timeStamping"
        when "1.3.6.1.5.5.7.3.9" then "ocspSigning"
        else oid
        end
      end
    end

    def parse_basic_constraints(cert)
      { ca: cert.getBasicConstraints >= 0, path_length: cert.getBasicConstraints }
    end

    def parse_subject_key_identifier(cert)
      val = cert.getExtensionValue("2.5.29.14")
      return nil unless val
      { key_id: bytes_to_hex(val) }
    end

    def parse_authority_key_identifier(cert)
      val = cert.getExtensionValue("2.5.29.35")
      return nil unless val
      { key_id: bytes_to_hex(val) }
    end

    def bytes_to_hex(bytes)
      return nil unless bytes
      bytes.map { |b| "%02X" % (b & 0xFF) }.join
    end
  end
end
