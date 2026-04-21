
java_import org.bouncycastle.jcajce.spec.MLKEMParameterSpec

module ApJavaCrypto
  module Engine
    class BCMLKEMEngine

      def self.generate_keypair(
        variant,
        bcPqProv,
        opts = %{}
      )
        
        benchmark = opts[:benchmark] || false

        kpg = java.security.KeyPairGenerator.get_instance('ML-KEM', bcPqProv)

        case variant
        when :ml_kem_512
          kpg.java_send(:initialize, [java.security.spec.AlgorithmParameterSpec], MLKEMParameterSpec.ml_kem_512)
        when :ml_kem_768
          kpg.java_send(:initialize, [java.security.spec.AlgorithmParameterSpec], MLKEMParameterSpec.ml_kem_768)
        when :ml_kem_1024
          kpg.java_send(:initialize, [java.security.spec.AlgorithmParameterSpec], MLKEMParameterSpec.ml_kem_1024)
        else
          raise StandardError, "Invalid ML-KEM variant #{variant}"
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

      def self.encapsulate(recp_pubkey, prov, opts = {})
       
        benchmark = opts[:benchmark] || false

        kf = java.security.KeyFactory.getInstance("ML-KEM", prov)
        pubkeyObj = kf.generatePublic(JcaJceCommon.load_public_key(recp_pubkey.binaryValue))

        start = BenchmarkUtils.mark_start() if benchmark
        kg = javax.crypto.KeyGenerator.get_instance("ML-KEM", prov)
        genSpec = org.bouncycastle.jcajce.spec.KEMGenerateSpec.new(pubkeyObj, "AES")
        kg.init(genSpec, java.security.SecureRandom.get_instance_strong())
        skEng = kg.generateKey()

        if benchmark
          [:ok, skEng.getEncoded(), skEng.get_encapsulation(), BenchmarkUtils.time_taken(start)]
        else
          [:ok, skEng.getEncoded(), skEng.get_encapsulation()]
        end

      end

      def self.decapsulate(cipher, privkey, prov, opts = {})
        
        benchmark = opts[:benchmark] || false
        
        kf = java.security.KeyFactory.getInstance("ML-KEM", prov)
        privKeyObj = kf.generatePrivate(JcaJceCommon.load_private_key(privkey.binaryValue))

        start = BenchmarkUtils.mark_start() if benchmark
        kg = javax.crypto.KeyGenerator.get_instance("ML-KEM", prov)
        exSpec = org.bouncycastle.jcajce.spec.KEMExtractSpec.new(privKeyObj, cipher.binaryValue, "AES")
        kg.init(exSpec, java.security.SecureRandom.get_instance_strong())
        skEng = kg.generateKey()

        if benchmark
          [:ok, skEng.getEncoded(),BenchmarkUtils.time_taken(start)]
        else
          [:ok, skEng.getEncoded()]
        end

      end

    end
  end
end
