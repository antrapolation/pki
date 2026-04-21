
java_import java.time.ZonedDateTime
java_import java.time.ZoneOffset

java_import com.antrapol.kaz.jcajce.kem.KAZKEMKeyGenParameterSpec

java_import com.ericsson.otp.erlang.OtpErlangAtom
java_import com.ericsson.otp.erlang.OtpErlangLong
java_import com.ericsson.otp.erlang.OtpErlangString

require_relative 'bc_x509'
require_relative 'jcajce_common'

module ApJavaCrypto
  module Engine
    class KAZKEMEngine

      def self.generate_keypair(
        variant,
        kazProv,
        opts = {}
      )
       benchmark = opts[:benchmark] || false

        kpg = java.security.KeyPairGenerator.get_instance('KAZ-KEM', kazProv)

        case variant
        when :kaz_kem_128
          kpg.java_send(:initialize, [java.security.spec.AlgorithmParameterSpec], KAZKEMKeyGenParameterSpec.KAZ_128)
        when :kaz_kem_192
          kpg.java_send(:initialize, [java.security.spec.AlgorithmParameterSpec], KAZKEMKeyGenParameterSpec.KAZ_192)
        when :kaz_kem_256
          kpg.java_send(:initialize, [java.security.spec.AlgorithmParameterSpec], KAZKEMKeyGenParameterSpec.KAZ_256)
        else
          raise StandardError, "Invalid KAZ-KEM variant #{variant}"
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

        pubkeyObj = com.antrapol.kaz.jcajce.kem.KAZKEMPublicKey.from_encoded(recp_pubkey.binaryValue)

        start = BenchmarkUtils.mark_start() if benchmark
        kg = javax.crypto.KeyGenerator.get_instance("KAZ-KEM", prov)
        genSpec = org.bouncycastle.jcajce.spec.KEMGenerateSpec.new(pubkeyObj, "AES")
        kg.init(genSpec, java.security.SecureRandom.get_instance_strong())
        skEng = kg.generateKey()

        if benchmark
          [:ok, skEng.getEncoded(), skEng.get_encapsulation(), BenchmarkUtils.time_taken(start)]
        else
          [:ok, skEng.getEncoded(), skEng.get_encapsulation()]
        end
        #kg = javax.crypto.KeyGenerator.getInstance("KAZ-KEM", "KAZ");
        #kemSender.init(new KEMGenerateSpec(receiverPublicKey, "AES"));
        #SecretKeyWithEncapsulation senderKey = (SecretKeyWithEncapsulation) kemSender.generateKey();
        #byte[] senderSharedSecret = senderKey.getEncoded();
        #byte[] encapsulation = senderKey.getEncapsulation();

        #[:ok, skEng.getEncoded(), skEng.get_encapsulation()]

      end

      def self.decapsulate(cipher, privkey, prov, opts = {})
        
        benchmark = opts[:benchmark] || false
        
        privkeyObj = com.antrapol.kaz.jcajce.kem.KAZKEMPrivateKey.from_encoded(privkey.binaryValue)

        start = BenchmarkUtils.mark_start() if benchmark
        kg = javax.crypto.KeyGenerator.get_instance("KAZ-KEM", prov)
        exSpec = org.bouncycastle.jcajce.spec.KEMExtractSpec.new(privkeyObj, cipher.binaryValue, "AES")
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
