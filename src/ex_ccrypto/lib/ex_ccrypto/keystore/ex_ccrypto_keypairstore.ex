defmodule ExCcrypto.Keystore.ExCcryptoKeypairstore do
  alias ExCcrypto.Keystore.ExCcryptoKeypairstore
  use TypedStruct

  typedstruct do
    field(:name, any())
    field(:keypair, any())
    field(:public_key, any())
    field(:cert, any())
    field(:cert_chain, any())
    field(:misc, any())
    field(:created_at, any())
    field(:created_on, any())
  end

  def build(keypair, cert, cert_chain \\ [], opts \\ %{})

  def build(kp, _, _, _) when is_nil(kp), do: {:error, :keypair_is_required}

  def build(keypair, cert, cert_chain, opts) do
    misc = Map.get(opts, :misc, %{})

    {:ok,
     %ExCcryptoKeypairstore{
       keypair: keypair,
       cert: cert,
       cert_chain: cert_chain,
       created_at: DateTime.utc_now(),
       created_on: node(),
       name: Map.get(opts, :name),
       misc: misc
     }}
  end

  def build_raw(keypair, public_key, opts \\ %{})

  def build_raw(keypair, _, _) when is_nil(keypair), do: {:error, :keypair_is_required}

  def build_raw(keypair, public_key, opts) do
    misc = Map.get(opts, :misc, %{})

    {:ok,
     %ExCcryptoKeypairstore{
       keypair: keypair,
       public_key: public_key,
       created_at: DateTime.utc_now(),
       created_on: node(),
       name: Map.get(opts, :name),
       misc: misc
     }}
  end

  def add_misc(%ExCcryptoKeypairstore{} = store, key, val) do
    %ExCcryptoKeypairstore{
      store
      | misc:
          case Map.has_key?(store.misc, key) do
            true -> Map.put(store.misc, key, val)
            false -> Map.put_new(store.misc, key, val)
          end
    }
  end

  def get_misc(%ExCcryptoKeypairstore{} = store, key), do: Map.get(store.misc, key)
end
