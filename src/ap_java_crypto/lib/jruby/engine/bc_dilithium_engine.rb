
java_import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec

module ApJavaCrypto
  module Engine
    class BcDilithiumEngine

      def self.generate_keypair(
        variant = :dilithium3, 
        bcPqProv
      )

        case variant
        when :dilithium2
          kpg = java.security.KeyPairGenerator.get_instance('dilithium2', bcPqProv)
          kpg.java_send(:initialize, [java.security.spec.AlgorithmParameterSpec], DilithiumParameterSpec.dilithium2)
          kp = kpg.generateKeyPair
          [:ok, :dilithium2, kp.get_private.get_encoded, kp.get_public.get_encoded]
        when :dilithium3
          kpg = java.security.KeyPairGenerator.get_instance('dilithium3', bcPqProv)
          kpg.java_send(:initialize, [java.security.spec.AlgorithmParameterSpec], DilithiumParameterSpec.dilithium3)
          kp = kpg.generateKeyPair
          [:ok, :dilithium3, kp.get_private.get_encoded, kp.get_public.get_encoded]

        when :dilithium5
          kpg = java.security.KeyPairGenerator.get_instance('dilithium5', bcPqProv)
          kpg.java_send(:initialize, [java.security.spec.AlgorithmParameterSpec], DilithiumParameterSpec.dilithium5)
          kp = kpg.generateKeyPair
          [:ok, :dilithium5, kp.get_private.get_encoded, kp.get_public.get_encoded]
        else
          raise StandardError, "Invalid Dilithium variant #{variant}"
        end

      end


      def self.sign(data, privkey, opts = {})
      end

      def self.verify(data, signature, pubkey, opts = {})
      end

    end
  end
end
