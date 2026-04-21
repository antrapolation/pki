defmodule ApJavaCrypto.X509.X509Certificate do
  # special case for ApJavaCrypto generated certificate
  def to_pem({:der, {:ap_java_crypto, _cert}} = cert) do
    ApJavaCrypto.x509_to_pem(cert)
  end

  def to_der({:pem, {:ap_java_crypto, _cert}} = cert) do
    ApJavaCrypto.x509_to_der(cert)
  end

  def is_issued_by?(
        {:der, {:ap_java_crypto, subject}},
        {:der, {:ap_java_crypto, issuer}}
      ) do
    with {:ok, true} <- ApJavaCrypto.cert_verify_issuer({:der, subject}, {:der, issuer}) do
      true
    else
      _ -> false
    end
  end

  def verify_certificate({:der, {:ap_java_crypto, subj}}, {:der, {:ap_java_crypto, iss}}) do
    with {:ok, true} <- ApJavaCrypto.verify_cert_validity({:der, subj}, :now),
         {:ok, true} <- ApJavaCrypto.cert_verify_issuer({:der, subj}, {:der, iss}) do
      true
    else
      _ -> false
    end
  end

  def cert_already_valid?({:der, {:ap_java_crypto, cert}}, ref) do
    with {:ok, true} <- ApJavaCrypto.verify_cert_validity({:der, cert}, ref) do
      true
    else
      _ -> false
    end
  end

  def cert_already_expired?({:der, {:ap_java_crypto, cert}}, ref) do
    with {:ok, true} <- ApJavaCrypto.verify_cert_validity({:der, cert}, ref) do
      true
    else
      _ -> false
    end
  end
end
