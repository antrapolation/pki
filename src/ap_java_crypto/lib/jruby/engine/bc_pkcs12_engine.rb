

module ApJavaCrypto
  module Engine
    class BcPKCS12Engine

      # owner certificate is 1st certificate inside the chain
      def self.generate_keystore(name, privkey, cert_chain, bcProv, opts = {})

        pprivkey = privkey.elements

        subjPrivKey = nil
        case pprivkey[0].atomValue
        when /^ml_dsa/
          kf = java.security.KeyFactory.getInstance("ML-DSA", bcProv)
          subjPrivKey = kf.generatePrivate(JcaJceCommon.load_private_key(pprivkey[2].binaryValue))
        when /^slh_dsa/
          kf = java.security.KeyFactory.getInstance("SLH-DSA", bcProv)
          subjPrivKey = kf.generatePrivate(JcaJceCommon.load_private_key(pprivkey[2].binaryValue))
        when /^kaz_sign/
          subjPrivKey = com.antrapol.kaz.jcajce.sign.KAZSIGNPrivateKey.from_encoded(pprivkey[2].binaryValue)
        when /^kaz_kem/
          subjPrivKey = com.antrapol.kaz.jcajce.kem.KAZKEMPrivateKey.from_encoded(pprivkey[2].binaryValue)
        else
          raise JrubyExPort::JrubyExPortException, "Unsupported private key algorithm #{pprivkey[0].atomValue}"
        end

        keypass = opts[:key_pass]
        keypass = java.lang.String.new(keypass).toCharArray if keypass != nil

        storepass = opts[:store_pass]
        storepass = java.lang.String.new(storepass).toCharArray if storepass != nil

        cchain = cert_chain.collect { |c| 
          CertificateFactory.get_instance("X.509", bcProv).generateCertificate(java.io.ByteArrayInputStream.new(Utils.erlang_to_ruby(c)))
        }.to_java(java.security.cert.Certificate)


        ks = java.security.KeyStore.getInstance("PKCS12", bcProv)
        ks.load(nil,nil)
        ks.setKeyEntry(java.lang.String.new(name.binaryValue), subjPrivKey, keypass, cchain)
        baos = java.io.ByteArrayOutputStream.new
        ks.store(baos, storepass)
        [:ok, baos.toByteArray]
      end

      def self.load_keystore(keystore, bcProv, opts = {})
      
        keypass = opts[:key_pass]
        keypass = java.lang.String.new(keypass).toCharArray if keypass != nil

        storepass = opts[:store_pass]
        storepass = java.lang.String.new(storepass).toCharArray if storepass != nil

        ks = java.security.KeyStore.getInstance("PKCS12", bcProv)
        ks.load(java.io.ByteArrayInputStream.new(keystore.binaryValue),storepass)

        rec = []
        ks.aliases.each do |a|
          res = {name: a}
          key = ks.getKey(a, keypass)
          res[:key] = {algo: key.getAlgorithm.to_sym, value: key.getEncoded}
          res[:cert] = ks.getCertificate(a).getEncoded
          res[:chain] = ks.getCertificateChain(a).collect { |c| c.getEncoded }

          rec << res
        end

          [:ok, rec]
      end

    end
  end
end
