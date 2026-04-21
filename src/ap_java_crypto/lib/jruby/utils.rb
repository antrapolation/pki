

java_import com.ericsson.otp.erlang.OtpErlangMap

module ApJavaCrypto
  module Utils

    def self.erlang_to_ruby_map(erlang_map)
      if erlang_map.is_a?(OtpErlangMap) 
        res = {}
        #puts erlang_map.values.to_java.class
        val = erlang_map.values.to_java
        erlang_map.keys.to_java.each_with_index do |k,indx|
          if k.is_a?(OtpErlangAtom)
            res[k.atomValue.to_sym] = erlang_to_ruby(val[indx])
          else
            res[k.binaryValue] = erlang_to_ruby(val[indx])
          end
        end

        res
      else
        raise JrubyExPort::JrubyExPortException, "Given Erlang object to conver to Ruby map is not a map : #{erlang_map}"
      end
    end

    def self.erlang_to_ruby(erlang_type)
      #puts "erlang_type : #{erlang_type.class}"
      if erlang_type.is_a?(OtpErlangAtom) 
        v = erlang_type.atomValue
        case v
        when "true"
          true
        when "false"
          false
        else
          erlang_type.atomValue.to_sym
        end
      else
        erlang_type.binaryValue
      end
    end

  end
end
