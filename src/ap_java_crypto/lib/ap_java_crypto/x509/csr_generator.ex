defmodule ApJavaCrypto.X509.CSRGenerator do
  alias ExCcrypto.ContextConfig
  alias ApJavaCrypto.SlhDsa.SlhDsaKeypair
  alias ApJavaCrypto.SlhDsa.SlhDsaPublicKey
  alias ApJavaCrypto.MlDsa.MlDsaPublicKey
  alias ApJavaCrypto.KazSign.KazSignPublicKey

  def generate(cert_owner, signer, opts \\ %{})

  def generate(%{public_key: %KazSignPublicKey{variant: var} = pubkey} = cert_owner, signer, opts)
      when var in [:kaz_sign_128, :kaz_sign_192, :kaz_sign_256] do
    cowner = %{cert_owner | public_key: {var, :public_key, pubkey.value}}

    # {:ok, {:der, csr}} =
    with {:ok, {:der, csr}} <-
           ApJavaCrypto.generate_csr(
             Map.from_struct(cowner),
             {signer.variant, :private_key, signer.value},
             opts
           ) do
      {:der, {:ap_java_crypto, csr}}
    end
  end

  def generate(%{public_key: %MlDsaPublicKey{variant: var} = pubkey} = cert_owner, signer, opts)
      when var in [:ml_dsa_44, :ml_dsa_65, :ml_dsa_87] do
    cowner = %{cert_owner | public_key: {var, :public_key, pubkey.value}}

    # {:ok, {:der, csr}} =
    with {:ok, {:der, csr}} <-
           ApJavaCrypto.generate_csr(
             Map.from_struct(cowner),
             {signer.variant, :private_key, signer.value},
             opts
           ) do
      {:der, {:ap_java_crypto, csr}}
    end
  end

  def generate(%{public_key: %SlhDsaPublicKey{variant: var} = pubkey} = cert_owner, signer, opts) do
    case Enum.member?(ContextConfig.get(%SlhDsaKeypair{}, :supported_variant), var) do
      true ->
        cowner = %{cert_owner | public_key: {var, :public_key, pubkey.value}}

        # {:ok, {:der, csr}} =
        with {:ok, {:der, csr}} <-
               ApJavaCrypto.generate_csr(
                 Map.from_struct(cowner),
                 {signer.variant, :private_key, signer.value},
                 opts
               ) do
          {:der, {:ap_java_crypto, csr}}
        end

      false ->
        raise "Unsupported SLH-DSA algorithm #{var}"
    end
  end
end
