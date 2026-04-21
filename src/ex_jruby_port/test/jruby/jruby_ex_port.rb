module JrubyExPort
  class RequiredFieldEmptyException < StandardError; end
  class NoDelegateFoundException < StandardError; end

  class PortProcess
    attr_accessor :port_node, :port_process_name, :caller_node, :caller_process, :otp_erlang_jar_path, :cookie,
                  :epmd_debug_level

    def initialize(argv)
      jconf = argv.split('/')
      @port_node = jconf[0]
      @port_process_name = jconf[1]
      @cookie = jconf[2]
      @caller_node = jconf[3]
      @caller_process = jconf[4]

      @epmd_debug_level = 0
      @callback = {}
    end

    def register(ops, &block)
      @callback[ops.to_sym] = block
    end

    def start
      verify_params(*%i[port_node port_process_name caller_node caller_process otp_erlang_jar_path cookie])

      java.lang.System.setProperty('OtpConnection.trace', @epmd_debug_level.to_s)

      require @otp_erlang_jar_path

      java_import com.ericsson.otp.erlang.OtpNode
      java_import com.ericsson.otp.erlang.OtpEpmd
      java_import com.ericsson.otp.erlang.OtpSelf
      java_import com.ericsson.otp.erlang.OtpConnection

      java_import com.ericsson.otp.erlang.OtpErlangObject
      java_import com.ericsson.otp.erlang.OtpErlangAtom
      java_import com.ericsson.otp.erlang.OtpErlangString
      java_import com.ericsson.otp.erlang.OtpErlangTuple
      java_import com.ericsson.otp.erlang.OtpErlangMap

      node = OtpNode.new(@port_node, @cookie)
      mbox = node.createMbox(@port_process_name)

      # reply = caller_line(mbox, @caller_node, @caller_process)
      reply = proc do |msg|
        mbox.send(@caller_process, @caller_node, msg)
      end

      notify_caller_port_ready(@port_node, @port_process_name) do |msg|
        reply.call(msg)
      end

      loop do
        val = mbox.receive
        # puts "val is #{val}"
        break if requested_to_stop(val)

        next unless val.is_a?(OtpErlangTuple)

        begin
          res = delegate(val.elements.to_a)
          reply_caller(reply, :ok, res)
        rescue StandardError => e
          reply_caller(reply, :error, e.message)
        end
      end

      # puts 'Process loop ends'
    end

    def reply_caller(reply, *value)
      vv = value.collect do |v|
        case v
        when Symbol
          OtpErlangAtom.new(v.to_s)
        else
          if !v.is_a?(OtpErlangObject)
            OtpErlangString.new(v)
          else
            v
          end
        end
      end

      reply.call(OtpErlangTuple.new(vv.to_java(OtpErlangObject)))
    end

    private

    def requested_to_stop(val)
      %w[stop done].include?(val.to_s)
    end

    def delegate(*params)
      val = params[0]
      ops = val[0].to_s.to_sym
      unless @callback.keys.include?(ops)
        raise NoDelegateFoundException,
              "No delegate register for operation '#{ops}'"
      end

      @callback[ops].call(*val[1..])
    end

    def notify_caller_port_ready(port_node, port_process_name, &block)
      res = []
      res << OtpErlangAtom.new('ok')

      resmsg = []
      resmsg << OtpErlangAtom.new('port_setup_completed')
      resmsg << OtpErlangAtom.new(port_node)
      resmsg << OtpErlangAtom.new(port_process_name)
      res << OtpErlangTuple.new(resmsg.to_java(OtpErlangObject))

      msg = OtpErlangTuple.new(res.to_java(OtpErlangObject))
      if block
        block.call(msg)
      else
        msg
      end
    end

    def verify_params(*para)
      para.each do |pa|
        val = instance_variable_get("@#{pa}".to_sym)
        raise RequiredFieldEmptyException, "Field '#{pa} is required but not given" if val.nil? or val.empty?
      end
    end
  end
end
