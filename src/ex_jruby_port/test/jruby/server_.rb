
jint_jar = File.join(File.expand_path(File.dirname(__FILE__)),"OtpErlang.jar")

require jint_jar

java_import com.ericsson.otp.erlang.OtpNode
java_import com.ericsson.otp.erlang.OtpEpmd
java_import com.ericsson.otp.erlang.OtpSelf
java_import com.ericsson.otp.erlang.OtpConnection

java_import com.ericsson.otp.erlang.OtpErlangObject
java_import com.ericsson.otp.erlang.OtpErlangAtom
java_import com.ericsson.otp.erlang.OtpErlangString
java_import com.ericsson.otp.erlang.OtpErlangTuple
java_import com.ericsson.otp.erlang.OtpErlangMap
java_import com.ericsson.otp.erlang.OtpInputStream
java_import com.ericsson.otp.erlang.OtpOutputStream

#bb = Java::byte.new[] {104, 2, 119, 2, 111, 107, 107, 0, 30, 102, 105, 114, 115, 116, 32, 58, 32, 104, 101, 108, 108, 111, 32, 47, 32, 115, 101, 99, 111, 110, 100, 32, 58, 32, 119, 111, 114, 108, 100}
bb = [104, 2, 119, 2, 111, 107, 107, 0, 30, 102, 105, 114, 115, 116, 32, 58, 32, 104, 101, 108, 108, 111, 32, 47, 32, 115, 101, 99, 111, 110, 100, 32, 58, 32, 119, 111, 114, 108, 100].to_java(Java::byte)

dec = OtpInputStream.new(bb).read_any
puts "decoded : #{dec}"

module RubyTest
  class RubyServer
    def self.say(first, second)
      puts "first : #{first} / second : #{second}"
      "first : #{first} / second : #{second}"
    end
  end
end

@input = IO.new(3)
@output = IO.new(4)
@output.sync = true
# @input = STDIN
# @output = STDOUT

def receive_input
  encoded_length = @input.read(4)
  return nil unless encoded_length

  length = encoded_length.unpack1('N')
  # @request_id, cmd = Erlang.binary_to_term(@input.read(length))
  #cmd = Erlang.binary_to_term(@input.read(length))
  cmd = OtpInputStream.new(@input.read(length).to_java_bytes).read_any()
  puts "Received command : #{cmd}"
  cmd
end

def send_response(value)
  # response = Erlang.term_to_binary(Erlang::Tuple[@request_id, value])
  #response = Erlang.term_to_binary(Erlang::Tuple[Erlang::Atom['ok'], value])

  if value == nil
    value = ""
  end
  #resp = OtpErlangTuple.new([OtpErlangAtom.new("ok"), OtpErlangString.new(value)].to_java(Java::ComEricssonOtpErlang::OtpErlangObject))
  resp = OtpErlangTuple.new([OtpErlangAtom.new("ok"), OtpErlangString.new(value)].to_java(OtpErlangObject))

  out = OtpOutputStream.new
  resp.encode(out)

  #puts "arity : #{resp.arity}"
  #out.write_tuple_head(resp.arity)

  #resp.elements.each do |e|
  #  out.write_any(e)
  #end

  response = out.toByteArray
  puts "response length : #{response.length}"

  rc = OtpInputStream.new(response).read_any
  puts "rc : #{rc}"

  #@output.write([response.bytesize].pack('N'))
  @output.write([response.length].pack('N'))
  @output.write(response)
  true
end

context = binding
while (cmd = receive_input)
  puts "Ruby Command: #{cmd.element_at(0)}\r"
  # puts "command : #{cmd[1]}.send(:#{cmd[2]}, *#{cmd[3].to_a})}"
  cls = cmd.element_at(1).binary_value
  puts "cls : #{cls}"
  mtd = cmd.element_at(2).binary_value
  puts "mtd : #{mtd}"
  params = cmd.element_at(3).elements.to_a.collect do |e|
    java.lang.String.new(e.binary_value)
  end
  puts "params : #{params}"
  res = if !cls.nil? and cls.size > 0
          eval("#{cls}.send(:#{mtd}, *#{params.to_a})", context, __FILE__, __LINE__)
        else
          eval("send(:#{mtd}, *#{params.to_a})", context, __FILE__, __LINE__)
        end
  # res = send(cmd[0], *cmd[1])
  # res = eval(cmd[1], context)
  puts "Eval result: #{res.inspect}\n\r"
  send_response(res)
end
puts 'Ruby: exiting'
