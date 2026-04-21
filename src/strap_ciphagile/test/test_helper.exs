# Start EPMD and a distributed node for JRuby
System.cmd("epmd", ["-daemon"])
Node.start(:test@localhost, :shortnames)

Application.ensure_all_started(:ex_ccrypto)
Application.ensure_all_started(:ap_java_crypto)
ExUnit.start()
