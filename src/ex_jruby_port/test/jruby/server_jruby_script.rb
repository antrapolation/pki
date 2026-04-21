require_relative 'jruby_ex_port'

require 'toolrack'

module RubyTest
  class RubyServer
    include TR::CondUtils
    def self.say(first, second)
      if not_empty?(first)
        puts "first : #{first} / second : #{second}"
        "running with script first : #{first} / second : #{second}"
      else
        "first is empty / second : #{second}"
      end
    end
  end
end

jpp = JrubyExPort::PortProcess.new(ARGV[0])
jpp.epmd_debug_level = 4
jpp.otp_erlang_jar_path = File.join(__dir__, 'OtpErlang.jar')

context = binding
jpp.register(:invoke) do |*params|
  cls = params[0].binary_value
  mtd = params[1].binary_value
  param = params[2].to_a.collect do |b|
    b.binary_value.to_s
  end

  eval("#{cls}.send(:#{mtd}, *#{param})", context, __FILE__, __LINE__)
end

jpp.register(:hello) do |*_pa|
  'hello JRuby from script'
end

jpp.start
