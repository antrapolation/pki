defmodule StrapSoftPrivKeyStoreProvider.Model.Keypair do
  use TypedStruct

  typedstruct do
    field(:purpose, any())
    field(:algo, any())
    field(:params, any())
    field(:value, any())
    field(:opts, any(), default: %{})
    field(:process_group_name, any())
    field(:landing_node, any())
  end
end

alias StrapPrivKeyStoreProvider.Protocol.KeypairEngine
alias StrapSoftPrivKeyStoreProvider.Model.Keypair

defimpl KeypairEngine, for: Keypair do
  alias StrapSoftPrivKeyStoreProvider.Model.SoftKeystore
  alias ExCcrypto.Asymkey.Asymkeystore
  alias StrapSoftPrivKeyStoreProvider.Model.Privkey
  alias StrapSoftPrivKeyStoreProvider.Model.Pubkey
  alias ExCcrypto.ContextConfig

  def keypair_purpose(%Keypair{} = kp, _opts), do: kp.purpose

  def to_keystore(%Keypair{} = kp, auth_token, opts) do
    # %{cipher: kscipher, cipher_context: ksctx}} <-
    with {:ok, bin} <-
           Asymkeystore.to_keystore(
             kp.value,
             Map.put_new(opts, :password, auth_token)
           ) do
      res = :erlang.binary_to_term(bin)

      {:ok,
       %SoftKeystore{
         store_type: :raw,
         enc_keypair: res,
         algo: kp.algo,
         params: kp.params,
         purpose: kp.purpose,
         process_group_name: kp.process_group_name,
         landing_node: kp.landing_node
       }}
    else
      res ->
        IO.puts("else")
        res
    end
  end

  def set_keypair_info(%Keypair{} = kp, key, value, _opts) do
    %Keypair{
      kp
      | opts:
          Map.get(kp, :opts, %{})
          |> Map.put(key, value)
    }
  end

  def remove_keypair_info(%Keypair{} = kp, key, _opts) do
    %Keypair{kp | opts: Map.delete(kp.opts, key)}
  end

  def get_keypair_info(%Keypair{} = kp, key, _opts), do: Map.get(kp.opts, key)

  def public_key(%Keypair{} = kp, _opts),
    do: %Pubkey{
      algo: kp.algo,
      params: kp.params,
      purpose: kp.purpose,
      value: ContextConfig.get(kp.value, :public_key),
      process_group_name: kp.process_group_name,
      landing_node: kp.landing_node
    }

  def private_key(%Keypair{} = kp, _opts),
    do: %Privkey{
      algo: kp.algo,
      params: kp.params,
      purpose: kp.purpose,
      value: ContextConfig.get(kp.value, :private_key),
      process_group_name: kp.process_group_name,
      landing_node: kp.landing_node
    }
end
