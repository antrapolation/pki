defmodule StrapSofthsmPrivKeyStoreProvider.Model.SofthsmKeystore do
  use TypedStruct

  typedstruct do
    field(:store_type, any())
    # Handle or label in HSM
    field(:key_id, any())
    field(:algo, any())
    field(:params, any())
    field(:opts, any())
    field(:purpose, any())
    field(:process_group_name, any())
    field(:landing_node, any())
  end
end

alias StrapSofthsmPrivKeyStoreProvider.Model.SofthsmKeystore
alias StrapPrivKeyStoreProvider.Protocol.KeystoreManagerProtocol
alias StrapPrivKeyStoreProvider.RemoteUtils

defimpl KeystoreManagerProtocol, for: SofthsmKeystore do
  def update_auth_token(ks, existing, new, opts) do
    RemoteUtils.call(
      ks.process_group_name,
      {:update_keystore_auth_token, ks, existing, new, opts}
    )
  end

  def to_keypair(ks, auth_token, opts) do
    RemoteUtils.call(ks.process_group_name, {:keystore_to_keypair, ks, auth_token, opts})
  end
end

alias StrapPrivKeyStoreProvider.Protocol.CertManagerProtocol

defimpl CertManagerProtocol, for: SofthsmKeystore do
  def generate_cert(ks, owner, issuer, opts) do
    RemoteUtils.call(ks.process_group_name, {:generate_cert, ks, owner, issuer, opts})
  end

  def issue_cert(ks, owner_or_csr, issuer, opts) do
    RemoteUtils.call(ks.process_group_name, {:issue_cert, ks, owner_or_csr, issuer, opts})
  end
end

alias StrapPrivKeyStoreProvider.Protocol.CSRGeneratorProtocol

defimpl CSRGeneratorProtocol, for: SofthsmKeystore do
  def generate(ks, owner, opts) do
    RemoteUtils.call(ks.process_group_name, {:generate_csr, ks, owner, opts})
  end
end
