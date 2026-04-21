defmodule X509.Certificate.Signer.CertSigner do
  require Record
  require Logger

  import X509.ASN1, except: [extension: 2]

  def sign_cert(tbs_cert, %{callback: cb, key_algo: _algo} = issuer_key) do
    Logger.debug("External certificate signer detected. #{inspect(issuer_key)}")

    tbs_cert_bin = :public_key.pkix_encode(:OTPTBSCertificate, tbs_cert, :otp)

    signAlgo = tbs_cert |> elem(3)
    {digest, _algo, opts} = :pubkey_cert.x509_pkix_sign_types(signAlgo)
    # signout = :public_key.sign(tbs_cert_bin, digest, issuer_key, opts)

    signout = cb.(tbs_cert_bin, digest, opts)

    c =
      otp_certificate(tbsCertificate: tbs_cert, signatureAlgorithm: signAlgo, signature: signout)

    :public_key.pkix_encode(:OTPCertificate, c, :otp)
  end

  def sign_cert(tbs_cert, issuer_key) do
    Logger.debug("Native private key signing")
    # Logger.debug("sign cert : #{inspect(tbs_cert)} ")
    # Logger.debug("tbs cert type : #{Record.is_record(tbs_cert)}")

    # enc = :public_key.pkix_encode(:OTPTBSCertificate, tbs_cert, :otp)
    # Logger.debug("pkix_encode tbs cert : #{inspect(enc)}")

    # signAlgo = tbs_cert |> elem(3)
    # {digest, _algo, opts} = :pubkey_cert.x509_pkix_sign_types(signAlgo)
    # signout = :public_key.sign(enc, digest, issuer_key, opts)
    # Logger.debug("signout : #{inspect(signout)}")
    # Logger.debug("issuer key : #{inspect(issuer_key)}")

    # c =
    # otp_certificate(tbsCertificate: tbs_cert, signatureAlgorithm: signAlgo, signature: signout)

    # last_enc = :public_key.pkix_encode(:OTPCertificate, c, :otp)
    # Logger.debug("last_enc : #{inspect(last_enc)}")

    res = :public_key.pkix_sign(tbs_cert, issuer_key)
    Logger.debug("pkix_sign result : #{inspect(res)}")

    res
  end
end
