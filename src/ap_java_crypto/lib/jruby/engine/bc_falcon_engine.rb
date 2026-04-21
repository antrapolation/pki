
java_import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec

module ApJavaCrypto
  module Engine
    class BcFalconEngine

      def self.generate_keypair(
        variant = :kyber768, 
        bcPqProv
      )

        kpg = java.security.KeyPairGenerator.get_instance('kyber', bcPqProv)

        case variant
        when :falcon512
          kpg = java.security.KeyPairGenerator.get_instance('falcon-512', bcPqProv)
          kpg.java_send(:initialize, [java.security.spec.AlgorithmParameterSpec], FalconParameterSpec.falcon_512)
          kp = kpg.generateKeyPair
          [:ok, variant, kp.get_private.get_encoded, kp.get_public.get_encoded]
        when :falcon1024
          kpg = java.security.KeyPairGenerator.get_instance('falcon-1024', bcPqProv)
          kpg.java_send(:initialize, [java.security.spec.AlgorithmParameterSpec], FalconParameterSpec.falcon_1024)
          kp = kpg.generateKeyPair
          [:ok, variant, kp.get_private.get_encoded, kp.get_public.get_encoded]

        else
          raise StandardError, "Invalid Falcon variant #{variant}"
        end

      end

    end
  end
end
