jint_jar = File.join(__dir__, 'OtpErlang.jar')

require jint_jar

java.lang.System.setProperty('OtpConnection.trace', '4')

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

module RubyTest
  class RubyServer
    def self.say(first, second)
      puts "first : #{first} / second : #{second}"
      "first : #{first} / second : #{second}"
    end
  end
end

conf = ARGV[0]
puts "argv : #{ARGV}"
jconf = conf.split('/')
port_node = jconf[0]
port_pname = jconf[1]
cookie = jconf[2]
caller_node = jconf[3]
caller_process = jconf[4]

node = OtpNode.new(port_node, cookie)
mbox = node.createMbox(port_pname)

res = []
res << OtpErlangAtom.new('ok')

resmsg = []
resmsg << OtpErlangAtom.new('port_setup_completed')
resmsg << OtpErlangAtom.new(port_node)
resmsg << OtpErlangAtom.new(port_pname)
res << OtpErlangTuple.new(resmsg.to_java(OtpErlangObject))

mbox.send(caller_process, caller_node, OtpErlangTuple.new(res.to_java(OtpErlangObject)))

stop = false
until stop
  val = mbox.receive
  puts "mbox received : #{val}"
end
