# frozen_string_literal: true

require_relative 'jruby_ex_port'

Dir.glob(File.join(File.dirname(__FILE__), '..', '..', 'jars', '*.jar')) do |f|
  p f
  require f
end

require_relative 'utils'
require_relative 'benchmark_utils'

java_import org.bouncycastle.jce.provider.BouncyCastleProvider
java_import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider
java_import com.antrapol.kaz.jcajce.KAZProvider



bcProv = BouncyCastleProvider.new
bcPQProv = BouncyCastlePQCProvider.new

java.security.Security.addProvider(bcProv)
java.security.Security.addProvider(bcPQProv)


kazProv = KAZProvider.new
java.security.Security.addProvider(kazProv)

module ApJavaCrypto
  BCProv = BouncyCastleProvider.new
  BCPQProv = BouncyCastlePQCProvider.new

  java.security.Security.addProvider(BCProv)
  java.security.Security.addProvider(BCPQProv)


  KAZProv = KAZProvider.new
  java.security.Security.addProvider(KAZProv)
end
#
require_relative "engine/bc_kyber_engine"
require_relative "engine/bc_dilithium_engine"
require_relative "engine/bc_falcon_engine"
require_relative "engine/bc_ecc_engine"

require_relative "engine/bc_ml_dsa_engine"
require_relative "engine/bc_slh_dsa_engine"
require_relative "engine/bc_ml_kem_engine"

require_relative "engine/kaz_sign_engine"
require_relative "engine/kaz_kem_engine"

require_relative "engine/bc_pkcs12_engine"
require_relative "engine/x509_parser"

# sr = java.security.SecureRandom.getInstanceStrong

jpp = JrubyExPort::PortProcess.new(ARGV[0])
jpp.epmd_debug_level = 4
jpp.otp_erlang_jar_path = File.join(File.dirname(__FILE__), '..', '..', 'jars', 'OtpErlang.jar')

jpp.register(:supported_pqc_signing_algo) do |*_pa|
  [:ok, [:kaz_sign_128, :kaz_sign_192, :kaz_sign_256, :ml_dsa_44, :ml_dsa_65, :ml_dsa_87, :slh_dsa_sha2_128f, :slh_dsa_sha2_128s, :slh_dsa_sha2_192f, :slh_dsa_sha2_192s,:slh_dsa_sha2_256f, :slh_dsa_sha2_256s,:slh_dsa_shake_128f, :slh_dsa_shake_128s, :slh_dsa_shake_192f, :slh_dsa_shake_192s,:slh_dsa_shake_256f, :slh_dsa_shake_256s]]
end

jpp.register(:supported_pqc_kem_algo) do |*_pa|
  [:ok, [:kaz_kem_128, :kaz_kem_192, :kaz_kem_256, :ml_kem_512, :ml_kem_768, :ml_kem_1024]]
end

jpp.register(:supported_ecc_curves) do |*_pa|
  [:ok, ApJavaCrypto::Engine::BcEccEngine.supported_curves()]
end

jpp.register(:generate_pkcs12) do |*params|
  name = params[0]
  privKey = params[1]
  cert_chain = params[2]

  opts = params[3]

  popts = nil
  if opts.is_a?(OtpErlangMap)
    popts = ApJavaCrypto::Utils.erlang_to_ruby_map(opts)
  else
    popts = {}
  end

  begin
    ApJavaCrypto::Engine::BcPKCS12Engine.generate_keystore(name, privKey, cert_chain, bcProv, popts)
  rescue StandardError => e
    puts e.backtrace.join("\n")
    [:error, e.message]
  end
end

jpp.register(:load_pkcs12) do |*params|
  keystore = params[0]
  opts = params[1]

  popts = nil
  if opts.is_a?(OtpErlangMap)
    popts = ApJavaCrypto::Utils.erlang_to_ruby_map(opts)
  else
    popts = {}
  end

  begin
    ApJavaCrypto::Engine::BcPKCS12Engine.load_keystore(keystore, bcProv, popts)
  rescue StandardError => e
    puts e.backtrace.join("\n")
    [:error, e.message]
  end

end

jpp.register(:generate_keypair) do |*params|
  algo = params[0]
  opts = params[1]

  popts = nil
  if opts.is_a?(OtpErlangMap)
    popts = ApJavaCrypto::Utils.erlang_to_ruby_map(opts)
  else
    popts = {}
  end

  case algo.atom_value
  when /^ml_kem/
    ApJavaCrypto::Engine::BCMLKEMEngine.generate_keypair(algo.atom_value.to_sym, bcProv, popts)

  when /^ml_dsa/
    ApJavaCrypto::Engine::BCMLDSAEngine.generate_keypair(algo.atom_value.to_sym, bcProv, popts)

  when /^slh_dsa/
    ApJavaCrypto::Engine::BCSLHDSAEngine.generate_keypair(algo.atom_value.to_sym, bcProv, popts)

  when /^falcon/
    ApJavaCrypto::Engine::BcFalconEngine.generate_keypair(algo.atom_value.to_sym, bcPQProv, popts)

  when /^kaz_sign/
    ApJavaCrypto::Engine::KAZSIGNEngine.generate_keypair(algo.atom_value.to_sym, kazProv, popts)

  when /^kaz_kem/
    ApJavaCrypto::Engine::KAZKEMEngine.generate_keypair(algo.atom_value.to_sym, kazProv, popts)

  when :ecc
    curve = params[1]
    ApJavaCrypto::Engine::BcEccEngine.generate_keypair(curve.atom_value.to_str, bcProv, popts)

  else
    puts "params : #{params}"

  end
rescue StandardError => e
  puts e.backtrace.join("\n")
  [:error, e.message]
end

jpp.register(:generate_csr) do |*params|
  owner = params[0]
  privkey = params[1].elements
  algo = privkey[0]

  opts = params[2]

  popts = nil
  if opts.is_a?(OtpErlangMap)
    popts = ApJavaCrypto::Utils.erlang_to_ruby_map(opts)
  else
    popts = {}
  end

  res = nil
  case algo.atom_value
  when /^ml_dsa/
    res = ApJavaCrypto::Engine::BCMLDSAEngine.generate_csr(owner, privkey[2], bcProv, bcProv, popts)
  
  when /^slh_dsa/
    res = ApJavaCrypto::Engine::BCSLHDSAEngine.generate_csr(owner, privkey[2], bcProv, bcProv, popts)

  when /^kaz_sign/
    res = ApJavaCrypto::Engine::KAZSIGNEngine.generate_csr(owner, privkey[2], kazProv, bcProv, popts)

  #when :ecc
  #  curve = params[1]
  #  ApJavaCrypto::Engine::BcEccEngine.generate_keypair(curve.atom_value.to_str, bcProv)

  else
    puts "params : #{params}"

  end
 
  res


rescue StandardError => e
  puts e.backtrace.join("\n")
  [:error, e.message]
end

# verify csr
jpp.register(:verify_csr) do |*params|
  csr = params[0]
  opts = params[1]

  puts "csr : #{csr}"

  popts = nil
  if opts.is_a?(OtpErlangMap)
    popts = ApJavaCrypto::Utils.erlang_to_ruby_map(opts)
  else
    popts = {}
  end

  ApJavaCrypto::Engine::BCX509.verify_csr(csr.binaryValue, bcProv, popts)

rescue StandardError => e
  puts e.backtrace.join("\n")
  [:error, e.message]
end



jpp.register(:sign) do |*params|
  algo = params[0]
  data = params[1]
  privKey = params[2]
  opts = params[3]

  popts = nil
  if opts.is_a?(OtpErlangMap)
    popts = ApJavaCrypto::Utils.erlang_to_ruby_map(opts)
  else
    popts = {}
  end


  case algo.atom_value
  when /^ml_kem/
    ApJavaCrypto::Engine::BCMLKEMEngine.generate_keypair(algo.atom_value.to_sym, bcProv, popts)

  when /^ml_dsa/
    ApJavaCrypto::Engine::BCMLDSAEngine.sign(data, privKey, bcProv, popts)

  when /^slh_dsa/
    ApJavaCrypto::Engine::BCSLHDSAEngine.sign(data, privKey, bcProv, popts)

  when /^falcon/
    ApJavaCrypto::Engine::BcFalconEngine.generate_keypair(algo.atom_value.to_sym, bcPQProv, popts)

  when /^kaz_sign/
    ApJavaCrypto::Engine::KAZSIGNEngine.sign(data, privKey, kazProv, popts)

  when :ecc
    curve = params[1]
    ApJavaCrypto::Engine::BcEccEngine.generate_keypair(curve.atom_value.to_str, bcProv, popts)

  else
    puts "params : #{params}"

  end
rescue StandardError => e
  puts e.backtrace.join("\n")
  [:error, e.message]
end

jpp.register(:verify) do |*params|
  algo = params[0]
  data = params[1]
  sign = params[2]
  pubkey = params[3]
  opts = params[4]

  puts "algo : #{algo.atom_value}"

  popts = nil
  if opts.is_a?(OtpErlangMap)
    popts = ApJavaCrypto::Utils.erlang_to_ruby_map(opts)
  else
    popts = {}
  end

  certPubKeyMode = false
  ppubkey = pubkey
  if pubkey.is_a?(OtpErlangTuple)
    ele = pubkey.elements
    if ele[0].atom_value.to_sym == :cert
      # certificate is given
      certPubKeyMode = true
      ppubkey = pubkey.elements[1]
    else
      raise JrubyExPort::JrubyExPortException, "Unsupported type '#{ele[0]}'"
    end
  end

  case algo.atom_value
  when /^ml_dsa/
    if certPubKeyMode
      ApJavaCrypto::Engine::BCMLDSAEngine.verify_with_cert(data, sign, ppubkey, bcProv, popts)
    else
      ApJavaCrypto::Engine::BCMLDSAEngine.verify(data, sign, ppubkey, bcProv, popts)
    end

  when /^slh_dsa/
    if certPubKeyMode
      ApJavaCrypto::Engine::BCSLHDSAEngine.verify_with_cert(data, sign, ppubkey, bcProv, popts)
    else
      ApJavaCrypto::Engine::BCSLHDSAEngine.verify(data, sign, ppubkey, bcProv, popts)
    end

  when /^kaz_sign/
    if certPubKeyMode
      ApJavaCrypto::Engine::KAZSIGNEngine.verify_with_cert(data, sign, ppubkey, kazProv, popts)
    else
      ApJavaCrypto::Engine::KAZSIGNEngine.verify(data, sign, ppubkey, kazProv, popts)
    end

  #when :ecc
  #  curve = params[1]
  #  ApJavaCrypto::Engine::BcEccEngine.generate_keypair(curve.atom_value.to_str, bcProv)

  else
    puts "params : #{params}"

  end
rescue StandardError => e
  puts e.backtrace.join("\n")
  [:error, e.message]
end

jpp.register(:issue_cert) do |*params|
  algo = params[0]
  cert_owner = params[1]
  cert_profile = params[2]
  opts = params[3]

  popts = nil
  if opts.is_a?(OtpErlangMap)
    popts = ApJavaCrypto::Utils.erlang_to_ruby_map(opts)
  else
    popts = {}
  end


  case algo.atom_value
  when /^ml_dsa/
    ApJavaCrypto::Engine::BCMLDSAEngine.issue_cert(cert_owner, cert_profile, bcProv, bcProv, popts)

  when /^slh_dsa/
    ApJavaCrypto::Engine::BCSLHDSAEngine.issue_cert(cert_owner, cert_profile, bcProv, bcProv, popts)
  #when :falcon512, :falcon1024
  #  ApJavaCrypto::Engine::BcFalconEngine.generate_keypair(algo.atom_value.to_sym, bcPQProv)

  when /^kaz_sign/
    ApJavaCrypto::Engine::KAZSIGNEngine.issue_cert(cert_owner, cert_profile, kazProv, bcProv, popts)

  #when :ecc
  #  curve = params[1]
  #  ApJavaCrypto::Engine::BcEccEngine.generate_keypair(curve.atom_value.to_str, bcProv)

  else
    puts "params : #{params}"

  end
rescue StandardError => e
  puts e.backtrace.join("\n")
  [:error, e.message]
end


jpp.register(:encapsulate) do |*params|
  algo = params[0]
  recp_pubkey = params[1]
  opts = params[2]

  popts = nil
  if opts.is_a?(OtpErlangMap)
    popts = ApJavaCrypto::Utils.erlang_to_ruby_map(opts)
  else
    popts = {}
  end

  case algo.atom_value
  when /^ml_kem/
    ApJavaCrypto::Engine::BCMLKEMEngine.encapsulate(recp_pubkey, bcProv, popts)

  when /^kaz_kem/, '1.3.6.1.4.1.62395.2.1.2'
    ApJavaCrypto::Engine::KAZKEMEngine.encapsulate(recp_pubkey, kazProv, popts)

  else
    puts "Unknown parameters for encapsulation : #{algo.atom_value}"

  end
rescue StandardError => e
  puts e.backtrace.join("\n")
  [:error, e.message]
end


jpp.register(:decapsulate) do |*params|
  algo = params[0]
  cipher = params[1]
  privKey = params[2]
  opts = params[3]

  popts = nil
  if opts.is_a?(OtpErlangMap)
    popts = ApJavaCrypto::Utils.erlang_to_ruby_map(opts)
  else
    popts = {}
  end

  case algo.atom_value
  when /^ml_kem/
    ApJavaCrypto::Engine::BCMLKEMEngine.decapsulate(cipher, privKey, bcProv, popts)

  when /^kaz_kem/
    ApJavaCrypto::Engine::KAZKEMEngine.decapsulate(cipher, privKey, kazProv, popts)

  else
    puts "Unknown parameters for decapsulation : #{algo.atom_value}"

  end
rescue StandardError => e
  puts e.backtrace.join("\n")
  [:error, e.message]
end


jpp.register(:parse_cert) do |*pa|
  certbin = pa[0]

  ApJavaCrypto::X509Parser.parse(certbin)
end

jpp.register(:cert_verify_issuer) do |*params|
  subject = params[0]
  issuer = params[1]
  opts = params[2]

  popts = nil
  if opts.is_a?(OtpErlangMap)
    popts = ApJavaCrypto::Utils.erlang_to_ruby_map(opts)
  else
    popts = {}
  end

  ApJavaCrypto::Engine::BCX509.cert_verify_issuer(subject, issuer, popts)

rescue StandardError => e
  puts e.backtrace.join("\n")
  [:error, e.message]
end

jpp.register(:verify_cert_validity) do |*params|
  subject = params[0]
  ref = params[1]
  opts = params[2]

  popts = nil
  if opts.is_a?(OtpErlangMap)
    popts = ApJavaCrypto::Utils.erlang_to_ruby_map(opts)
  else
    popts = {}
  end

  ApJavaCrypto::Engine::BCX509.verify_cert_validity(subject, ref , popts)

rescue Java::JavaSecurityCert::CertificateNotYetValidException => ex
  [:error, [:certficate_not_yet_valid, ex.message]]

rescue Java::JavaSecurityCert::CertificateExpiredException => ex
  [:error, [:certficate_already_expired, ex.message]]

rescue java.lang.Exception => ex
  puts ex.class
  [:error, ex.message]

rescue StandardError => e
  puts e.backtrace.join("\n")
  [:error, e.message]

end



jpp.register(:hello) do |*_pa|
  'hello JRuby'
end

jpp.start
