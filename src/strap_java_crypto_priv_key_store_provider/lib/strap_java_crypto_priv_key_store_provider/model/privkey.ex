defmodule StrapJavaCryptoPrivKeyStoreProvider.Model.Privkey do
  use TypedStruct

  typedstruct do
    field(:algo, any())
    field(:params, any())
    field(:value, any())
    field(:purpose, any())
    field(:process_group_name, any())
    field(:landing_node, any())
  end
end

alias StrapJavaCryptoPrivKeyStoreProvider.Model.Privkey
alias StrapPrivKeyStoreProvider.Protocol.PrivateKeyOps

defimpl PrivateKeyOps, for: Privkey do
  alias StrapJavaCryptoPrivKeyStoreProvider.Model.Pubkey

  def sign_data(%Privkey{} = privkey, data, opts) do
    group_name = Map.get(opts, :crypto_group, :ap_java_crypto)
    safe_opts = Map.drop(opts, [:timeout])
    # ApJavaCrypto wrappers expect Tuples and unwrap them
    key_tuple = privkey.value

    ApJavaCrypto.sign(data, key_tuple, Map.put(safe_opts, :group_name, group_name))
  end

  def decrypt_data(
        %Privkey{} = privkey,
        %Pubkey{} = _pubkey,
        cipher,
        opts
      ) do
    # Assuming this is KEM decapsulation since ApJavaCrypto is PQC focused
    group_name = Map.get(opts, :crypto_group, :ap_java_crypto)
    safe_opts = Map.drop(opts, [:timeout])
    key_tuple = privkey.value

    # ApJavaCrypto.decapsulate(cipher, privkey, opts)
    with {:ok, secret} <-
           ApJavaCrypto.decapsulate(
             cipher,
             key_tuple,
             Map.put(safe_opts, :group_name, group_name)
           ) do
      {:ok, secret}
    else
      {:ok, secret, _addr} -> {:ok, secret}
      err -> err
    end
  end
end
