

module ApJavaCrypto

  module Engine
   
    class JcaJceCommon

      def self.load_private_key(val)
        java.security.spec.PKCS8EncodedKeySpec.new(val)
      end

      def self.load_public_key(val)
        java.security.spec.X509EncodedKeySpec.new(val)
      end
      
      def self.sign(data, signature_engine_name, privKey, prov, opts = {})

        benchmark = opts[:benchmark] || false

        sign = java.security.Signature.getInstance(signature_engine_name, prov) 
        start = BenchmarkUtils.mark_start() if benchmark

        sign.initSign(privKey)
        sign.update(data.to_java)
        res = sign.sign()

        if benchmark
          [:ok, res, BenchmarkUtils.time_taken(start)]
        else
          [:ok, res]
        end
      end

      def self.verify(data, signature_engine_name, signature, pubkey, prov, opts = {})
        
        benchmark = opts[:benchmark] || false

        ver = java.security.Signature.getInstance(signature_engine_name, prov) 
        start = BenchmarkUtils.mark_start() if benchmark

        ver.initVerify(pubkey)
        ver.update(data.to_java)
        res = ver.verify(signature.to_java)

        if benchmark
          if res
            [:ok, :true, BenchmarkUtils.time_taken(start)]
          else
            [:error, :false, BenchmarkUtils.time_taken(start)]
          end
        else
          if res
            [:ok, :true]
          else
            [:error, :false]
          end
        end

      end


    end

  end
  
end
