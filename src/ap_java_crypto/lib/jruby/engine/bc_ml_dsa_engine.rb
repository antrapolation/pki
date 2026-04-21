
java_import org.bouncycastle.jcajce.spec.MLDSAParameterSpec

module ApJavaCrypto
  module Engine
    class BCMLDSAEngine

      def self.generate_keypair(
        variant,
        bcPqProv,
        opts = {}
      )

        benchmark = opts[:benchmark] || false

        kpg = java.security.KeyPairGenerator.get_instance('ML-DSA', bcPqProv)

        case variant
        when :ml_dsa_44
          kpg.java_send(:initialize, [java.security.spec.AlgorithmParameterSpec], MLDSAParameterSpec.ml_dsa_44)

        when :ml_dsa_65
          kpg.java_send(:initialize, [java.security.spec.AlgorithmParameterSpec], MLDSAParameterSpec.ml_dsa_65)

        when :ml_dsa_87
          kpg.java_send(:initialize, [java.security.spec.AlgorithmParameterSpec], MLDSAParameterSpec.ml_dsa_87)

        else
          raise StandardError, "Invalid ML-DSA variant #{variant}"
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

        kf = java.security.KeyFactory.getInstance("ML-DSA", prov)
        privKeyObj = kf.generatePrivate(JcaJceCommon.load_private_key(privKey.binaryValue))

        JcaJceCommon.sign(data.binaryValue, "ML-DSA", privKeyObj, prov, opts)
      end

      def self.verify(data, signature, pubkey, prov, opts = {})
        kf = java.security.KeyFactory.getInstance("ML-DSA", prov)
        pubkeyObj = kf.generatePublic(JcaJceCommon.load_public_key(pubkey.binaryValue))

        JcaJceCommon.verify(data.binaryValue, "ML-DSA", signature.binaryValue, pubkeyObj, prov, opts)
      end

      def self.verify_with_cert(data, signature, cert, prov, opts = {})
        
        puts "Verify via X509 Certificate ML-DSA"

        certObj = BCX509.to_java_cert(cert)
        pubkeyObj = certObj.get_public_key

        JcaJceCommon.verify(data.binaryValue, "ML-DSA", signature.binaryValue, pubkeyObj, prov, opts)

      end


      def self.generate_csr(cert_owner, signing_key, prov, bcProv, opts = {})
        
        benchmark = opts[:benchmark] || false

        isskey = signing_key.binaryValue
        kf = java.security.KeyFactory.getInstance("ML-DSA", prov)
        signingKey = kf.generatePrivate(JcaJceCommon.load_private_key(isskey))

        start = BenchmarkUtils.mark_start() if benchmark
        res = BCX509.generate_csr(cert_owner, signingKey, bcProv, Proc.new do |ops|
          case ops
          when :content_signer_builder
            org.bouncycastle.operator.jcajce.JcaContentSignerBuilder.new("ML-DSA").setProvider(bcProv).build(signingKey)
          else
            raise JrubyExPort::JrubyExPortException, "Callback operation for CSR generation not supported : #{ops}"
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
        kf = java.security.KeyFactory.getInstance("ML-DSA", prov)
        signingKey = kf.generatePrivate(JcaJceCommon.load_private_key(isskey))

        start = BenchmarkUtils.mark_start() if benchmark
        res = BCX509.issue_cert(cert_owner, cert_profile, prov, bcProv,  Proc.new do |ops|
          case ops
          when :content_signer_builder
            org.bouncycastle.operator.jcajce.JcaContentSignerBuilder.new("ML-DSA").setProvider(bcProv).build(signingKey)
          else
            raise JrubyExPort::JrubyExPortException, "Callback operation for certificate issuance not supported : #{ops}"
          end
        end)

        if benchmark
          res << BenchmarkUtils.time_taken(start)
        else
          res
        end
      end


    end
  end
end
