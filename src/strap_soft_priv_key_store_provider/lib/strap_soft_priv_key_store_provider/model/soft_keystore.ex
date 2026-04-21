defmodule StrapSoftPrivKeyStoreProvider.Model.SoftKeystore do
  use TypedStruct

  typedstruct do
    field(:store_type, any())
    field(:enc_keypair, any())
    field(:algo, any())
    field(:params, any())
    field(:opts, any())
    field(:purpose, any())
    field(:process_group_name, any())
    field(:landing_node, any())
  end
end

alias StrapSoftPrivKeyStoreProvider.Model.SoftKeystore
alias StrapPrivKeyStoreProvider.Protocol.KeystoreManagerProtocol

defimpl KeystoreManagerProtocol, for: SoftKeystore do
  alias StrapPrivKeyStoreProvider.Protocol.KeypairEngine
  alias StrapSoftPrivKeyStoreProvider.Model.Keypair
  alias ExCcrypto.Asymkey.AsymkeystoreLoader

  def update_auth_token(%SoftKeystore{} = ks, existing, new, _opts) do
    with {:ok, keypair} <- KeystoreManagerProtocol.to_keypair(ks, existing),
         {:ok, keystore} <- KeypairEngine.to_keystore(keypair, new) do
      {:ok, keystore}
    end
  end

  def to_keypair(%SoftKeystore{} = ks, auth_token, _opts) do
    with {:ok, kp} <-
           AsymkeystoreLoader.from_keystore(
             ks.enc_keypair,
             %{password: auth_token}
           ) do
      {:ok,
       %Keypair{
         algo: ks.algo,
         value: kp,
         params: ks.params,
         purpose: ks.purpose,
         process_group_name: ks.process_group_name,
         landing_node: ks.landing_node
       }}
    end
  end
end

alias StrapPrivKeyStoreProvider.Protocol.CertManagerProtocol

defimpl CertManagerProtocol, for: SoftKeystore do
  alias ExCcrypto.ContextConfig
  alias ExCcrypto.X509.CertGenerator
  alias ExCcrypto.X509.CertProfile
  alias ExCcrypto.X509.CertOwner

  # self-sign 
  def generate_cert(%SoftKeystore{} = ks, %CertOwner{} = owner, %CertProfile{} = issuer, opts) do
    auth_token = Map.get(opts, :keystore_auth_token)

    with {:ok, keypair} <- KeystoreManagerProtocol.to_keypair(ks, auth_token) do
      privKey = ContextConfig.get(keypair.value, :private_key)
      pubKey = ContextConfig.get(keypair.value, :public_key)

      cowner =
        case issuer.self_sign do
          true -> CertOwner.set_public_key(owner, pubKey)
          false -> owner
        end

      {:ok,
       CertGenerator.generate(
         CertProfile.set_issuer_key(issuer, privKey),
         cowner
       )}
    end
  end

  def issuer_cert(_, _, _, %{issuer_cert: ic}) when is_nil(ic),
    do: {:error, :issuer_cert_is_required}

  def issue_cert(%SoftKeystore{} = ks, %CertOwner{} = owner, %CertProfile{} = issuer, opts) do
    auth_token = Map.get(opts, :keystore_auth_token)
    issuer_cert = Map.get(opts, :issuer_cert)

    with {:ok, keypair} <- KeystoreManagerProtocol.to_keypair(ks, auth_token) do
      privKey = ContextConfig.get(keypair.value, :private_key)

      {:ok,
       CertGenerator.generate(
         CertProfile.set_issuer_key(issuer, privKey) |> CertProfile.set_issuer_cert(issuer_cert),
         owner
       )}
    end
  end

  def issue_cert(%SoftKeystore{} = ks, {:native, csr}, %CertProfile{} = issuer, opts) do
    auth_token = Map.get(opts, :keystore_auth_token)
    issuer_cert = Map.get(opts, :issuer_cert)

    with {:ok, keypair} <- KeystoreManagerProtocol.to_keypair(ks, auth_token) do
      privKey = ContextConfig.get(keypair.value, :private_key)

      {:ok,
       CertGenerator.generate(
         CertProfile.set_issuer_key(issuer, privKey) |> CertProfile.set_issuer_cert(issuer_cert),
         csr
       )}
    end
  end

  def issue_cert(_, csr, _, _), do: {:error, {:native_csr_expected, csr}}
end

alias StrapPrivKeyStoreProvider.Protocol.CSRGeneratorProtocol

defimpl CSRGeneratorProtocol, for: SoftKeystore do
  alias ExCcrypto.ContextConfig
  alias ExCcrypto.X509.CSRGenerator
  alias ExCcrypto.X509.CertOwner

  def generate(%SoftKeystore{} = ks, %CertOwner{} = owner, opts) do
    auth_token = Map.get(opts, :keystore_auth_token)
    output = Map.get(opts, :output_format, :bin)

    with {:ok, keypair} <- KeystoreManagerProtocol.to_keypair(ks, auth_token) do
      privKey = ContextConfig.get(keypair.value, :private_key)

      {:ok, format_csr(CSRGenerator.generate(owner, privKey), output)}
    end
  end

  defp format_csr(csr, :bin), do: csr
  defp format_csr(csr, :pem), do: CSRGenerator.to_pem(csr)
end
