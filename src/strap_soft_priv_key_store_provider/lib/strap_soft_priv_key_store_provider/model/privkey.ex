defmodule StrapSoftPrivKeyStoreProvider.Model.Privkey do
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

alias StrapSoftPrivKeyStoreProvider.Model.Privkey
alias StrapPrivKeyStoreProvider.Protocol.PrivateKeyOps

defimpl PrivateKeyOps, for: Privkey do
  alias StrapSoftPrivKeyStoreProvider.Model.Pubkey
  alias ExCcrypto.Asymkey.AsymkeyDecrypt
  alias ExCcrypto.Asymkey.AsymkeySign
  alias ExCcrypto.ContextConfig
  alias ExCcrypto.Asymkey.AsymkeySignContextBuilder

  def sign_data(%Privkey{} = privkey, data, _opts) do
    AsymkeySignContextBuilder.sign_context(privkey.algo)
    |> ContextConfig.set(:private_key, privkey.value)
    |> AsymkeySign.sign_init()
    |> AsymkeySign.sign_update(data)
    |> AsymkeySign.sign_final()
  end

  def decrypt_data(
        %Privkey{} = privkey,
        %Pubkey{} = pubkey,
        enc,
        _opts
      ) do
    with {:ok, ctx} <- AsymkeyDecrypt.decrypt_init(enc, pubkey.value, privkey.value) do
      res =
        AsymkeyDecrypt.decrypt_update(ctx, enc.cipher)
        |> AsymkeyDecrypt.decrypt_final()

      {:ok, res}
    else
      err -> {:error, err}
    end
  end
end
