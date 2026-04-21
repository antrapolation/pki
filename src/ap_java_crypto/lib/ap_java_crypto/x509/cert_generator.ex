defmodule ApJavaCrypto.X509.CertGenerator do
  # alias ExCcrypto.X509.CertOwner
  alias ApJavaCrypto.SlhDsa.SlhDsaPrivateKey
  alias ApJavaCrypto.MlDsa.MlDsaPrivateKey
  alias ApJavaCrypto.KazSign.KazSignPrivateKey

  require Logger

  def generate(
        %{issuer_cert: {:pem, {:ap_java_crypto, _pem}} = cert} = cert_profile,
        owner
      ) do
    generate(%{cert_profile | issuer_cert: ApJavaCrypto.x509_to_der(cert)}, owner)
  end

  # CSR come here
  def generate(
        %{issuer_key: %KazSignPrivateKey{} = priv} = cert_profile,
        {:der, {:ap_java_crypto, csr}}
      ) do
    Logger.debug("KAZ-SIGN cert gen using CSR!")

    cprof = %{cert_profile | issuer_key: {priv.variant, :private_key, priv.value}}

    # {:ok, {:der, cert}} =
    with {:ok, {:der, cert}} <-
           ApJavaCrypto.issue_certificate(
             {:der, csr},
             Map.from_struct(cprof)
           ) do
      {:der, {:ap_java_crypto, cert}}
    end
  end

  def generate(
        %{issuer_key: %MlDsaPrivateKey{} = priv} = cert_profile,
        {:der, {:ap_java_crypto, csr}}
      ) do
    Logger.debug("ML-DSA cert gen using CSR!")

    cprof = %{cert_profile | issuer_key: {priv.variant, :private_key, priv.value}}

    # {:ok, {:der, cert}} =
    with {:ok, {:der, cert}} <-
           ApJavaCrypto.issue_certificate(
             {:der, csr},
             Map.from_struct(cprof)
           ) do
      {:der, {:ap_java_crypto, cert}}
    end
  end

  def generate(
        %{issuer_key: %SlhDsaPrivateKey{} = priv} = cert_profile,
        {:der, {:ap_java_crypto, csr}}
      ) do
    Logger.debug("SLH-DSA cert gen using CSR!")

    cprof = %{cert_profile | issuer_key: {priv.variant, :private_key, priv.value}}

    # {:ok, {:der, cert}} =
    with {:ok, {:der, cert}} <-
           ApJavaCrypto.issue_certificate(
             {:der, csr},
             Map.from_struct(cprof)
           ) do
      {:der, {:ap_java_crypto, cert}}
    end
  end

  def generate(%{issuer_key: %KazSignPrivateKey{} = priv} = cert_profile, cert_owner) do
    Logger.debug("KAZ-SIGN cert gen!")

    # IO.puts("cert_owner : #{inspect(cert_owner)}")

    cprof = %{cert_profile | issuer_key: {priv.variant, :private_key, priv.value}}
    cowner = %{cert_owner | public_key: Map.from_struct(cert_owner.public_key)}

    Logger.debug("generate with cert_owner : #{inspect(cowner)}")

    # {:ok, {:der, cert}} =
    with {:ok, {:der, cert}} <-
           ApJavaCrypto.issue_certificate(
             Map.from_struct(cowner),
             Map.from_struct(cprof)
           ) do
      {:der, {:ap_java_crypto, cert}}
    end
  end

  def generate(%{issuer_key: %MlDsaPrivateKey{} = priv} = cert_profile, cert_owner) do
    Logger.debug("ML-DSA cert gen!")

    # IO.puts("cert_owner : #{inspect(cert_owner)}")

    cprof = %{cert_profile | issuer_key: {priv.variant, :private_key, priv.value}}
    cowner = %{cert_owner | public_key: Map.from_struct(cert_owner.public_key)}

    Logger.debug("generate with cert_owner : #{inspect(cowner)}")

    # {:ok, {:der, cert}} =
    with {:ok, {:der, cert}} <-
           ApJavaCrypto.issue_certificate(
             Map.from_struct(cowner),
             Map.from_struct(cprof)
           ) do
      {:der, {:ap_java_crypto, cert}}
    end
  end

  def generate(%{issuer_key: %SlhDsaPrivateKey{} = priv} = cert_profile, cert_owner) do
    Logger.debug("SLH-DSA cert gen!")

    # IO.puts("cert_owner : #{inspect(cert_owner)}")

    cprof = %{cert_profile | issuer_key: {priv.variant, :private_key, priv.value}}
    cowner = %{cert_owner | public_key: Map.from_struct(cert_owner.public_key)}

    Logger.debug("generate with cert_owner : #{inspect(cowner)}")

    # {:ok, {:der, cert}} =
    with {:ok, {:der, cert}} <-
           ApJavaCrypto.issue_certificate(
             Map.from_struct(cowner),
             Map.from_struct(cprof)
           ) do
      {:der, {:ap_java_crypto, cert}}
    end
  end
end
