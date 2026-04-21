
java_import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec

module ApJavaCrypto
  module Engine
    class BcKyberEngine

      def self.generate_keypair(
        variant = :kyber768, 
        bcPqProv
      )

        kpg = java.security.KeyPairGenerator.get_instance('kyber', bcPqProv)

        case variant
        when :kyber512
          kpg.java_send(:initialize, [java.security.spec.AlgorithmParameterSpec], KyberParameterSpec.kyber512)
        when :kyber768
          kpg.java_send(:initialize, [java.security.spec.AlgorithmParameterSpec], KyberParameterSpec.kyber768)
        when :kyber1024
          kpg.java_send(:initialize, [java.security.spec.AlgorithmParameterSpec], KyberParameterSpec.kyber1024)
        else
          raise StandardError, "Invalid Kyber variant #{variant}"
        end

        kp = kpg.generateKeyPair
        [:ok, variant, kp.get_private.get_encoded, kp.get_public.get_encoded]
      end

    end
  end
end
