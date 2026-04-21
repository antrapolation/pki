defmodule StrapJavaCryptoPrivKeyStoreProvider.Model.Pubkey do
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

alias StrapJavaCryptoPrivKeyStoreProvider.Model.Pubkey
alias StrapPrivKeyStoreProvider.Protocol.PublicKeyOps

defimpl PublicKeyOps, for: Pubkey do
  def verify_data(%Pubkey{} = pub, data, signature, opts) do
    group_name = Map.get(opts, :crypto_group, :ap_java_crypto)
    safe_opts = Map.drop(opts, [:timeout])
    key_tuple = pub.value

    ApJavaCrypto.verify(data, signature, key_tuple, Map.put(safe_opts, :group_name, group_name))
  end

  def encrypt_data(%Pubkey{} = pub, _data, opts) do
    # KEM Encapsulation takes no data (input), it generates shared secret and cipher
    # But PublicKeyOps.encrypt_data takes data.
    # If the user intends to allow KEM, they might pass empty data or we ignore it?
    # Or maybe we are encrypting the "data"?
    # KEM != Encryption.
    # But protocol is named encrypt_data.
    # For KEM, usually we encapsulate to get a shared secret, then use that to encrypt the data.
    # If ApJavaCrypto only supports encapsulation, then we can only return {secret, cipher}.
    # But `encrypt_data` generally implies returning just the Ciphertext (and maybe the IV/Tag if implicit).
    # If I just call encapsulate, I return {secret, cipher}.

    # However, existing implementations (SoftProvider) use AsymkeyEncrypt.encrypt... which allows encrypting DATA.
    # If ApJavaCrypto is purely PQC KEM, it doesn't "encrypt data" directly with the asymmetric key.
    # It encapsulates a key.

    # The user request asks to "implement ... backed by ApJavaCrypto".
    # ApJavaCrypto has `encapsulate`.
    # I'll map `encrypt_data` to `encapsulate` and ignore the `data` arg if strictly KEM, OR
    # if the intention is to encrypt `data`, I might need a hybrid scheme?
    # But ApJavaCrypto doesn't seem to offer hybrid encryption helper in the file I read.
    # It just exposes `encapsulate`.

    # I will stick to `encapsulate` and return the result.

    group_name = Map.get(opts, :crypto_group, :ap_java_crypto)
    safe_opts = Map.drop(opts, [:timeout])
    key_tuple = pub.value

    with {:ok, secret, cipher} <-
           ApJavaCrypto.encapsulate(key_tuple, Map.put(safe_opts, :group_name, group_name)) do
      # We return a map or tuple representing the result.
      {:ok, %{secret: secret, cipher: cipher}}
    else
      {:ok, secret, cipher, _addr} -> {:ok, %{secret: secret, cipher: cipher}}
      err -> err
    end
  end
end
