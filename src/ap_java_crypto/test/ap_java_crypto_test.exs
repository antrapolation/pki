defmodule ApJavaCryptoTest do
  alias ExJrubyPort.JrubyService
  alias ExJrubyPort.JrubyJarContext
  use ExUnit.Case
  doctest ApJavaCrypto

  # 
  # Test internal API - KAZ-SIGN-128
  #
  test "Internal Signing API Test" do
    assert {:ok, pid} = ExJrubyPort.start_link(%JrubyJarContext{})

    assert {:ok, spid} =
             ExJrubyPort.start_node(pid, "./lib/jruby/java_crypto.rb")

    algo = :kaz_sign_128

    assert {:ok, algo, privKey, pubKey} =
             res =
             JrubyService.call(spid, {:generate_keypair, algo})

    IO.inspect(res)
    assert privKey != nil
    assert pubKey != nil

    assert {:ok, algo, privKey, pubKey, addres} =
             JrubyService.call(spid, {:generate_keypair, algo, %{benchmark: true}})

    IO.inspect(addres)
    assert privKey != nil
    assert pubKey != nil

    data = "data to be signed with #{algo}"
    assert {:ok, signature} = sres = JrubyService.call(spid, {:sign, algo, data, privKey})
    IO.inspect(sres)

    assert {:ok, true} = JrubyService.call(spid, {:verify, algo, data, signature, pubKey})

    # 
    # Benchmark test 
    #
    data = "data to be signed with #{algo}, return benchmark"

    assert {:ok, signature, addres} =
             sres = JrubyService.call(spid, {:sign, algo, data, privKey, %{benchmark: true}})

    IO.inspect(sres)

    assert {:ok, true, addres} =
             JrubyService.call(
               spid,
               {:verify, algo, data, signature, pubKey, %{benchmark: true}}
             )

    assert addres != nil

    assert {:error, false} =
             JrubyService.call(spid, {:verify, algo, "wrong data", signature, pubKey})

    assert {:ok, cert, chain} =
             JrubyService.call(
               spid,
               {:issue_cert, algo,
                %{name: "Testing #{algo}", public_key: {algo, :public_key, pubKey}},
                %{
                  issuer_key: privKey,
                  is_issuer: true,
                  self_sign: true,
                  key_usage: [],
                  ext_key_usage: []
                }}
             )

    IO.puts("Certificate size : #{byte_size(cert)}")

    File.write!("cert.cer", cert)

    certb64 = Base.encode64(cert)

    File.write!(
      "cert.crt",
      "-----BEGIN CERTIFICATE-----\n#{certb64}\n-----END CERTIFICATE-----\n"
    )

    assert {:ok, cert, chain, addres} =
             JrubyService.call(
               spid,
               {:issue_cert, algo,
                %{name: "Testing #{algo}", public_key: {algo, :public_key, pubKey}},
                %{
                  issuer_key: privKey,
                  is_issuer: true,
                  self_sign: true,
                  key_usage: [],
                  ext_key_usage: []
                }, %{benchmark: true}}
             )

    assert addres != nil

    assert {:ok, csr} =
             JrubyService.call(
               spid,
               {:generate_csr,
                %{
                  name: "CSR Owner",
                  org: "Antrapol",
                  org_unit: "Security",
                  country: "MY",
                  public_key: {algo, :public_key, pubKey}
                }, {algo, :private_key, privKey}}
             )

    assert {:ok, true} =
             JrubyService.call(
               spid,
               {:verify_csr, csr}
             )

    assert {:ok, true, csr_info} =
             JrubyService.call(
               spid,
               {:verify_csr, csr, %{return_csr_info: true}}
             )

    IO.inspect(csr_info)
    assert csr_info != nil

    assert {:ok, csr, addres} =
             JrubyService.call(
               spid,
               {:generate_csr,
                %{
                  name: "CSR Owner",
                  org: "Antrapol",
                  country: "MY",
                  org_unit: "ID - YDan",
                  email: "CSRowner@owner.com",
                  public_key: {algo, :public_key, pubKey}
                }, {algo, :private_key, privKey}, %{benchmark: true}}
             )

    assert addres != nil
    IO.inspect(addres)

    assert {:ok, ccert, _chain} =
             JrubyService.call(
               spid,
               {:issue_cert, algo, csr,
                %{
                  issuer_key: privKey,
                  is_issuer: true,
                  self_sign: true,
                  key_usage: [],
                  ext_key_usage: [],
                  validity: {8, :year}
                }}
             )

    IO.puts("certificate for verification : #{inspect(ccert)}")

    assert {:ok, true} =
             JrubyService.call(
               spid,
               {:cert_verify_issuer, ccert, ccert}
             )

    assert {:error, reason} =
             JrubyService.call(
               spid,
               {:cert_verify_issuer, ccert, cert}
             )

    assert {:ok, true} =
             JrubyService.call(
               spid,
               {:verify_cert_validity, ccert}
             )

    assert {ok, info} =
             JrubyService.call(
               spid,
               {:parse_cert, ccert}
             )

    IO.inspect(info)

    File.write!("cert_from_csr.cer", ccert)

    assert {:ok, ccert, chain, addres} =
             JrubyService.call(
               spid,
               {:issue_cert, algo, csr,
                %{
                  issuer_key: privKey,
                  is_issuer: true,
                  self_sign: true,
                  key_usage: [:digital_signature, :crl_sign, :key_cert_sign],
                  ext_key_usage: [:ocsp_signing],
                  validity: [{5, :year}, {4, :hour}, {30, :min}]
                }, %{benchmark: true}}
             )

    assert addres != nil

    # 
    # verify by certificate
    #
    assert {:ok, true} =
             JrubyService.call(spid, {:verify, algo, data, signature, {:cert, ccert}})

    assert {:ok, p12} =
             JrubyService.call(
               spid,
               {:generate_pkcs12, "testp12", {algo, :private_key, privKey}, [ccert] ++ chain,
                %{key_pass: "keypass", store_pass: "storepass"}}
             )

    File.write!("test.p12", p12)

    assert {:ok, p12} =
             JrubyService.call(
               spid,
               {:generate_pkcs12, "testp12-nopass", {algo, :private_key, privKey},
                [ccert] ++ chain, %{store_pass: "storepass"}}
             )

    assert {:ok, ksCont} =
             JrubyService.call(
               spid,
               {:load_pkcs12, p12, %{store_pass: "storepass"}}
             )

    cont = List.first(ksCont)

    IO.inspect(cont)
    assert Map.get(cont, :name) == "testp12-nopass"
    assert Map.get(cont, :key).value == privKey
    assert Map.get(cont, :cert) == ccert

    assert {ok, info} =
             JrubyService.call(
               spid,
               {:parse_cert, ccert}
             )

    IO.inspect(info)
  end

  # 
  # Test internal API - ALL Algo
  #
  test "Internal Signing API Test - All algo" do
    assert {:ok, pid} = ExJrubyPort.start_link(%JrubyJarContext{})

    assert {:ok, spid} =
             ExJrubyPort.start_node(pid, "./lib/jruby/java_crypto.rb")

    assert {:ok, algos} = JrubyService.call(spid, {:supported_pqc_signing_algo})

    Enum.each(
      algos,
      fn algo ->
        assert {:ok, algo, privKey, pubKey} =
                 res =
                 JrubyService.call(spid, {:generate_keypair, algo})

        IO.inspect(res)
        assert privKey != nil
        assert pubKey != nil

        assert {:ok, algo, privKey, pubKey, addres} =
                 JrubyService.call(spid, {:generate_keypair, algo, %{benchmark: true}})

        IO.inspect(addres)
        assert privKey != nil
        assert pubKey != nil

        data = "data to be signed with #{algo}"
        assert {:ok, signature} = sres = JrubyService.call(spid, {:sign, algo, data, privKey})
        IO.inspect(sres)

        assert {:ok, true} = JrubyService.call(spid, {:verify, algo, data, signature, pubKey})

        # 
        # Benchmark test 
        #
        data = "data to be signed with #{algo}, return benchmark"

        assert {:ok, signature, addres} =
                 sres = JrubyService.call(spid, {:sign, algo, data, privKey, %{benchmark: true}})

        IO.inspect(sres)

        assert {:ok, true, addres} =
                 JrubyService.call(
                   spid,
                   {:verify, algo, data, signature, pubKey, %{benchmark: true}}
                 )

        assert addres != nil

        assert {:error, false} =
                 JrubyService.call(spid, {:verify, algo, "wrong data", signature, pubKey})

        assert {:ok, cert, chain} =
                 JrubyService.call(
                   spid,
                   {:issue_cert, algo,
                    %{name: "Testing #{algo}", public_key: {algo, :public_key, pubKey}},
                    %{
                      issuer_key: privKey,
                      is_issuer: true,
                      self_sign: true,
                      key_usage: [],
                      ext_key_usage: []
                    }}
                 )

        IO.puts("Certificate size : #{byte_size(cert)}")

        File.write!("cert.cer", cert)

        certb64 = Base.encode64(cert)

        File.write!(
          "cert.crt",
          "-----BEGIN CERTIFICATE-----\n#{certb64}\n-----END CERTIFICATE-----\n"
        )

        assert {:ok, cert, chain, addres} =
                 JrubyService.call(
                   spid,
                   {:issue_cert, algo,
                    %{name: "Testing #{algo}", public_key: {algo, :public_key, pubKey}},
                    %{
                      issuer_key: privKey,
                      is_issuer: true,
                      self_sign: true,
                      key_usage: [],
                      ext_key_usage: []
                    }, %{benchmark: true}}
                 )

        assert addres != nil

        assert {:ok, csr} =
                 JrubyService.call(
                   spid,
                   {:generate_csr, %{name: "CSR Owner", public_key: {algo, :public_key, pubKey}},
                    {algo, :private_key, privKey}}
                 )

        assert {:ok, csr, addres} =
                 JrubyService.call(
                   spid,
                   {:generate_csr,
                    %{
                      name: "CSR Owner",
                      org: "Antrapol",
                      country: "MY",
                      org_unit: "ID - YDan",
                      email: "CSRowner@owner.com",
                      public_key: {algo, :public_key, pubKey}
                    }, {algo, :private_key, privKey}, %{benchmark: true}}
                 )

        assert addres != nil
        IO.inspect(addres)

        assert {:ok, true} =
                 JrubyService.call(
                   spid,
                   {:verify_csr, csr}
                 )

        assert {:ok, true, csr_info} =
                 JrubyService.call(
                   spid,
                   {:verify_csr, csr, %{return_csr_info: true}}
                 )

        IO.inspect(csr_info)
        assert csr_info != nil

        assert {:ok, ccert, _chain} =
                 JrubyService.call(
                   spid,
                   {:issue_cert, algo, csr,
                    %{
                      issuer_key: privKey,
                      is_issuer: true,
                      self_sign: true,
                      key_usage: [],
                      ext_key_usage: []
                    }}
                 )

        File.write!("cert_from_csr.cer", ccert)

        assert {:ok, ccert, chain, addres} =
                 JrubyService.call(
                   spid,
                   {:issue_cert, algo, csr,
                    %{
                      issuer_key: privKey,
                      is_issuer: true,
                      self_sign: true,
                      key_usage: [:digital_signature, :crl_sign, :key_cert_sign],
                      ext_key_usage: [:ocsp_signing],
                      validity: [{5, :year}, {8, :hour}, {30, :min}]
                    }, %{benchmark: true}}
                 )

        assert addres != nil

        # 
        # verify by certificate
        #
        assert {:ok, true} =
                 JrubyService.call(spid, {:verify, algo, data, signature, {:cert, ccert}})

        assert {:ok, p12} =
                 JrubyService.call(
                   spid,
                   {:generate_pkcs12, "testp12", {algo, :private_key, privKey}, [ccert] ++ chain,
                    %{key_pass: "keypass", store_pass: "storepass"}}
                 )

        File.write!("test.p12", p12)

        assert {:ok, p12} =
                 JrubyService.call(
                   spid,
                   {:generate_pkcs12, "testp12-nopass", {algo, :private_key, privKey},
                    [ccert] ++ chain, %{store_pass: "storepass"}}
                 )

        assert {:ok, ksCont} =
                 JrubyService.call(
                   spid,
                   {:load_pkcs12, p12, %{store_pass: "storepass"}}
                 )

        assert {:ok, true} =
                 JrubyService.call(
                   spid,
                   {:cert_verify_issuer, ccert, ccert}
                 )

        assert {:error, reason} =
                 JrubyService.call(
                   spid,
                   {:cert_verify_issuer, ccert, cert}
                 )

        assert {:ok, true} =
                 JrubyService.call(
                   spid,
                   {:verify_cert_validity, ccert}
                 )

        cont = List.first(ksCont)

        IO.inspect(cont)
        assert Map.get(cont, :name) == "testp12-nopass"

        assert Map.get(cont, :key).value == privKey
        assert Map.get(cont, :cert) == ccert

        IO.puts("cert before parse : #{inspect(ccert)}")

        assert {ok, info} =
                 JrubyService.call(
                   spid,
                   {:parse_cert, ccert}
                 )

        IO.inspect(info)

        assert info != nil
      end
    )
  end

  # 
  # Test all PQC signing algo via external API
  #
  test "External Signing API test - All PQC Signing algo" do
    ApJavaCrypto.start_link()

    assert {:ok, algos} = ApJavaCrypto.supported_pqc_signing_algo()

    Enum.each(
      algos,
      fn algo ->
        assert {:ok, priv, pub} = ApJavaCrypto.generate_keypair(algo)
        assert {algo, :private_key, privkeybin} = priv
        assert {algo, :public_key, pubkeybin} = pub

        assert {:ok, priv, pub, addres} = ApJavaCrypto.generate_keypair(algo, %{benchmark: true})
        IO.inspect(addres)
        assert addres != nil
        assert {algo, :private_key, privkeybin} = priv
        assert {algo, :public_key, pubkeybin} = pub

        data = "data for signing from external with algo #{algo}"
        assert {:ok, sign} = ApJavaCrypto.sign(data, priv)

        assert {:ok, true} = ApJavaCrypto.verify(data, sign, pub)
        assert {:error, false} = ApJavaCrypto.verify("random data", sign, pub)

        data = "data for benchmark signing from external with algo #{algo}"
        assert {:ok, sign, addres} = ApJavaCrypto.sign(data, priv, %{benchmark: true})

        assert {:ok, true, addres} = ApJavaCrypto.verify(data, sign, pub, %{benchmark: true})

        assert {:error, false, addres} =
                 ApJavaCrypto.verify("random data", sign, pub, %{benchmark: true})

        assert {:ok, {:der, cert}} =
                 ApJavaCrypto.issue_certificate(
                   %{name: "Jack", email: "JackBauer@24.com", public_key: pub},
                   %{
                     issuer_key: priv,
                     is_issuer: true,
                     self_sign: true,
                     key_usage: [],
                     ext_key_usage: []
                   }
                 )

        File.write!("cert2.cer", cert)

        certb64 = Base.encode64(cert)

        File.write!(
          "cert2.crt",
          "-----BEGIN CERTIFICATE-----\n#{certb64}\n-----END CERTIFICATE-----\n"
        )

        assert {:ok, {:der, cert} = cert1, addres} =
                 ApJavaCrypto.issue_certificate(
                   %{name: "Jack", email: "JackBauer@24.com", public_key: pub},
                   %{
                     issuer_key: priv,
                     is_issuer: true,
                     self_sign: true,
                     key_usage: [],
                     ext_key_usage: []
                   },
                   %{benchmark: true}
                 )

        assert addres != nil
        IO.inspect(addres)

        assert {:ok, {:der, csr} = csrres} =
                 ApJavaCrypto.generate_csr(
                   %{name: "CSR Jack", email: "jack-bauer@24.com", public_key: pub},
                   priv
                 )

        File.write!("extapi.csr", csr)

        assert {:ok, {:der, csr} = csrres, addres} =
                 ApJavaCrypto.generate_csr(
                   %{name: "CSR Jack", email: "jack-bauer@24.com", public_key: pub},
                   priv,
                   %{benchmark: true}
                 )

        assert addres != nil
        IO.inspect(addres)

        assert {:ok, true} = ApJavaCrypto.verify_csr(csrres)

        assert {:ok, true, csr_info} = ApJavaCrypto.verify_csr(csrres, %{return_csr_info: true})

        IO.inspect(csr_info)
        assert csr_info != nil

        assert {:ok, {:der, ccert} = gcert} =
                 ApJavaCrypto.issue_certificate(
                   csrres,
                   %{
                     issuer_key: priv,
                     is_issuer: true,
                     self_sign: true,
                     key_usage: [],
                     ext_key_usage: []
                   }
                 )

        File.write!("cert2_from_csr.cer", ccert)

        assert {:ok, {:der, ccert} = gcert, addres} =
                 ApJavaCrypto.issue_certificate(
                   csrres,
                   %{
                     issuer_key: priv,
                     is_issuer: true,
                     self_sign: true,
                     key_usage: [:digital_signature, :key_cert_sign, :crl_sign],
                     ext_key_usage: [:ocsp_signing],
                     validity: [{8, :year}, {8, :hour}, {45, :min}]
                   },
                   %{benchmark: true}
                 )

        assert addres != nil
        IO.inspect(addres)

        IO.puts("Certificate for verification (high level API) : #{inspect(ccert)}")
        assert {:ok, true} = ApJavaCrypto.cert_verify_issuer(gcert, gcert)

        assert {:error, reason} = ApJavaCrypto.cert_verify_issuer(gcert, cert1)

        assert {:ok, true} = ApJavaCrypto.verify_cert_validity(gcert)

        assert {:ok, true} = ApJavaCrypto.verify(data, sign, {:cert, ccert})

        assert {:ok, p12} =
                 ApJavaCrypto.generate_p12("external test", priv, gcert, [gcert], %{
                   store_pass: "password"
                 })

        assert {:ok, store_items} =
                 ApJavaCrypto.load_p12(p12, %{store_pass: "password"})

        {ralgo, :private_key, privVal} = priv
        assert ralgo == algo

        cont = List.first(store_items)

        IO.inspect(cont)
        assert Map.get(cont, :name) == "external test"
        assert Map.get(cont, :key).value == privVal
        assert Map.get(cont, :cert) == ccert

        assert {ok, info} = ApJavaCrypto.parse_cert(ccert)

        IO.inspect(info)

        assert {:error, _msg} =
                 ApJavaCrypto.load_p12(p12, %{store_pass: "wrong pass"})
      end
    )
  end

  # 
  # Test internal API - ALL KEM algo
  #
  test "Internal KEM API Test" do
    assert {:ok, pid} = ExJrubyPort.start_link(%JrubyJarContext{})

    assert {:ok, spid} =
             ExJrubyPort.start_node(pid, "./lib/jruby/java_crypto.rb")

    assert {:ok, algos} = JrubyService.call(spid, {:supported_pqc_kem_algo})

    Enum.each(
      algos,
      fn algo ->
        assert {:ok, algo, privKey, pubKey} =
                 res =
                 JrubyService.call(spid, {:generate_keypair, algo})

        IO.inspect(res)
        assert privKey != nil
        assert pubKey != nil

        assert {:ok, algo, privKey2, pubKey2, addres} =
                 JrubyService.call(spid, {:generate_keypair, algo, %{benchmark: true}})

        IO.inspect(addres)
        assert privKey2 != nil
        assert pubKey2 != nil

        assert {:ok, secret, cipher} =
                 res = JrubyService.call(spid, {:encapsulate, algo, pubKey2})

        IO.inspect(res)

        assert {:ok, secret, cipher, addres} =
                 res = JrubyService.call(spid, {:encapsulate, algo, pubKey2, %{benchmark: true}})

        assert addres != nil
        IO.inspect(res)

        assert {:ok, secret2} =
                 res2 = JrubyService.call(spid, {:decapsulate, algo, cipher, privKey2})

        IO.inspect(res2)
        assert secret2 == secret

        assert {:ok, secret3, addres} =
                 res3 =
                 JrubyService.call(
                   spid,
                   {:decapsulate, algo, cipher, privKey, %{benchmark: true}}
                 )

        assert addres != nil
        IO.inspect(res3)
        assert secret3 != secret
      end
    )
  end

  # 
  # Test all external API - KEM algo
  #
  test "External KEM API test" do
    ApJavaCrypto.start_link()

    assert {:ok, algos} = ApJavaCrypto.supported_pqc_kem_algo()

    Enum.each(
      algos,
      fn algo ->
        assert {:ok, priv, pub} = ApJavaCrypto.generate_keypair(algo)
        assert {algo, :private_key, privkeybin} = priv
        assert {algo, :public_key, pubkeybin} = pub

        assert {:ok, priv, pub, addres} = ApJavaCrypto.generate_keypair(algo, %{benchmark: true})
        IO.inspect(addres)
        assert addres != nil
        assert {algo, :private_key, privkeybin} = priv
        assert {algo, :public_key, pubkeybin} = pub

        assert {:ok, secret, cipher} = ApJavaCrypto.encapsulate(pub)
        assert {:ok, secret, cipher, addres} = ApJavaCrypto.encapsulate(pub, %{benchmark: true})
        assert secret != nil
        assert addres != nil

        assert {:ok, secret2} = ApJavaCrypto.decapsulate(cipher, priv)
        assert {:ok, secret2, addres} = ApJavaCrypto.decapsulate(cipher, priv, %{benchmark: true})
        assert secret2 != nil
        assert addres != nil

        assert secret2 == secret
      end
    )
  end
end
