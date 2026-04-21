
java_import com.ericsson.otp.erlang.OtpErlangAtom

module ApJavaCrypto
  module Engine
    class BcEccEngine
      def self.supported_curves()
        org.bouncycastle.asn1.x9.ECNamedCurveTable.getNames.sort.to_a.map do |c|
          OtpErlangAtom.new(c)
        end
      end

      def self.generate_keypair(curve, bcProv)
        kpg = java.security.KeyPairGenerator.getInstance("ECDSA", bcProv)
        randomEngine = java.security.SecureRandom.new
        kpg.java_send :initialize, [java.security.spec.AlgorithmParameterSpec, randomEngine.class], java.security.spec.ECGenParameterSpec.new(curve), randomEngine
        kp = kpg.generate_key_pair
        [:ok, [:ecc, curve], kp.get_private.get_encoded, kp.get_public.get_encoded]
      end

    end
  end
end
